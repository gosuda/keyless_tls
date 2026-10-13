package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/internal/admission"
	"github.com/gosuda/keyless_tls/internal/testutil"
	"github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

func TestServerTLSConfig_WithMTLS(t *testing.T) {
	serverCertPEM, serverKeyPEM, err := testutil.GenerateCert("test.local", false)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	clientCAPEM, _, err := testutil.GenerateCert("test.local", true)
	if err != nil {
		t.Fatalf("create client CA cert: %v", err)
	}

	tlsConf, err := serverTLSConfig(serverCertPEM, serverKeyPEM, clientCAPEM)
	if err != nil {
		t.Fatalf("serverTLSConfig() error = %v", err)
	}
	if tlsConf.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("expected ClientAuth=%v, got %v", tls.RequireAndVerifyClientCert, tlsConf.ClientAuth)
	}
	if tlsConf.ClientCAs == nil {
		t.Fatal("expected ClientCAs to be set when mTLS is enabled")
	}
}

func TestServerTLSConfig_WithoutMTLS(t *testing.T) {
	serverCertPEM, serverKeyPEM, err := testutil.GenerateCert("test.local", false)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	tlsConf, err := serverTLSConfig(serverCertPEM, serverKeyPEM, nil)
	if err != nil {
		t.Fatalf("serverTLSConfig() error = %v", err)
	}
	if tlsConf.ClientAuth != tls.NoClientCert {
		t.Fatalf("expected ClientAuth=%v, got %v", tls.NoClientCert, tlsConf.ClientAuth)
	}
	if tlsConf.ClientCAs != nil {
		t.Fatal("expected ClientCAs to be nil when mTLS is disabled")
	}
}

func TestServerTLSConfig_InvalidCAPEM(t *testing.T) {
	serverCertPEM, serverKeyPEM, err := testutil.GenerateCert("test.local", false)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	_, err = serverTLSConfig(serverCertPEM, serverKeyPEM, []byte("not-valid-pem"))
	if err == nil {
		t.Fatal("expected error for invalid client CA PEM")
	}
}

func TestSignHandler_Success(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	service := &signer.Service{
		Store:       staticStore{signer: priv},
		AllowedSkew: 30 * time.Second,
		// The handler-level test exercises the signing path without a
		// transcript validator, which is the library primitive; validator
		// rejection is covered in relay/signer tests.
	}
	h := signHandler(service)

	body, err := json.Marshal(signrpc.TranscriptSignRequest{
		KeyID:               "relay-cert",
		Algorithm:           signrpc.AlgorithmRSAPSSSHA256,
		Binding:             []byte{0x01},
		ClientHello:         []byte("client-hello"),
		ServerHello:         []byte("server-hello"),
		EncryptedExtensions: []byte("encrypted-extensions"),
		Certificate:         []byte("certificate"),
		TimestampUnix:       time.Now().Unix(),
		Nonce:               "abc",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, signrpc.SignPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}

	var resp signrpc.TranscriptSignResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.KeyID != "relay-cert" {
		t.Fatalf("unexpected key id: %s", resp.KeyID)
	}
	if len(resp.Signature) == 0 {
		t.Fatal("expected signature in response")
	}
}

func TestSignHandler_RejectsLegacyDigestContract(t *testing.T) {
	// Compatibility matrix: the /v1/sign wire contract is transcript-bound.
	// The request below is a fully valid legacy digest-shaped request — a
	// digest-schema server would sign it — so rejection here pins the
	// intentional protocol break, not an incidental crypto error.
	h := signHandler(&signer.Service{Store: staticStore{signer: mustRSAKey(t)}})

	digest := sha256.Sum256([]byte("hello"))
	body, err := json.Marshal(map[string]any{
		"key_id":         "relay-cert",
		"algorithm":      signrpc.AlgorithmRSAPSSSHA256,
		"digest":         digest[:],
		"timestamp_unix": time.Now().Unix(),
		"nonce":          "abc",
	})
	if err != nil {
		t.Fatalf("marshal legacy request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, signrpc.SignPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected legacy digest request to be rejected with 400, got %d, body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "missing required handshake transcript field") {
		t.Fatalf("expected transcript-contract rejection reason, got: %s", rr.Body.String())
	}
}

func TestSignHandler_MethodNotAllowed(t *testing.T) {
	h := signHandler(&signer.Service{Store: staticStore{signer: mustRSAKey(t)}})
	req := httptest.NewRequest(http.MethodGet, signrpc.SignPath, nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", rr.Code)
	}
	if rr.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("allow header = %q", rr.Header().Get("Allow"))
	}
}

func TestSignHandler_MapsServiceError(t *testing.T) {
	h := signHandler(&signer.Service{Store: staticStore{err: io.EOF}})
	body, err := json.Marshal(signrpc.TranscriptSignRequest{
		KeyID:               "relay-cert",
		Algorithm:           signrpc.AlgorithmRSAPSSSHA256,
		Binding:             []byte{0x01},
		ClientHello:         []byte("client-hello"),
		ServerHello:         []byte("server-hello"),
		EncryptedExtensions: []byte("encrypted-extensions"),
		Certificate:         []byte("certificate"),
		TimestampUnix:       time.Now().Unix(),
		Nonce:               "abc",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, signrpc.SignPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
}

type staticStore struct {
	signer crypto.Signer
	err    error
}

func (s staticStore) Signer(context.Context, string) (crypto.Signer, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.signer, nil
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func validSignBody(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(signrpc.TranscriptSignRequest{
		KeyID: "relay-cert", Algorithm: signrpc.AlgorithmRSAPSSSHA256,
		Nonce: "nonce", TimestampUnix: time.Now().Unix(),
		ClientHello: []byte("ch"), ServerHello: []byte("sh"),
		EncryptedExtensions: []byte("ee"), Certificate: []byte("cert"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestSignHandler_PerCertificateRateLimit(t *testing.T) {
	h := signHandlerWithLimits(&signer.Service{Store: staticStore{signer: mustRSAKey(t)}},
		admission.Limits{MaxConcurrent: 8, MaxPerIdentity: 2, MaxIdentities: 8, RatePerSecond: 1, Burst: 1})
	body := validSignBody(t)
	send := func(cert *x509.Certificate, address string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, signrpc.SignPath, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = address
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	certA := &x509.Certificate{Raw: []byte("client A")}
	certB := &x509.Certificate{Raw: []byte("client B")}
	if rr := send(certA, "192.0.2.1:123"); rr.Code != http.StatusOK {
		t.Fatalf("initial signing status = %d: %s", rr.Code, rr.Body.String())
	}
	// Changing IP must not reset the mTLS identity's token bucket.
	if rr := send(certA, "192.0.2.2:123"); rr.Code != http.StatusTooManyRequests ||
		rr.Header().Get("Retry-After") != "1" {
		t.Fatalf("identity rate limit status = %d: %s", rr.Code, rr.Body.String())
	}
	if rr := send(certB, "192.0.2.2:123"); rr.Code != http.StatusOK {
		t.Fatalf("independent client status = %d: %s", rr.Code, rr.Body.String())
	}
}

type heldSigner struct {
	entered chan struct{}
	release <-chan struct{}
}

func (s *heldSigner) Public() crypto.PublicKey { return nil }

func (s *heldSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	s.entered <- struct{}{}
	<-s.release
	return []byte{1}, nil
}

func TestSignHandler_MapsSignerOverloadTo429(t *testing.T) {
	release := make(chan struct{})
	blocker := &heldSigner{entered: make(chan struct{}, 1), release: release}
	svc := &signer.Service{
		Store: staticStore{signer: blocker},
		MaxConcurrentSigns: 1,
		MaxConcurrentSignsPerKey: 1,
	}
	h := signHandler(svc)
	body := validSignBody(t)
	send := func(addr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, signrpc.SignPath, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = addr
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- send("192.0.2.1:1111") }()
	select {
	case <-blocker.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first sign operation did not start")
	}
	overloaded := send("192.0.2.2:2222")
	if overloaded.Code != http.StatusTooManyRequests || overloaded.Header().Get("Retry-After") != "1" {
		t.Fatalf("overload status = %d: %s", overloaded.Code, overloaded.Body.String())
	}
	if got := svc.RejectedSigns(); got != 1 {
		t.Fatalf("overload metric = %d, want 1", got)
	}
	close(release)
	select {
	case result := <-first:
		if result.Code != http.StatusOK {
			t.Fatalf("first request status = %d: %s", result.Code, result.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("admitted signing did not finish after releasing its slot")
	}
}
