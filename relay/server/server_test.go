package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
