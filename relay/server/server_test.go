package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

func TestServerTLSConfig_RequiresClientCA(t *testing.T) {
	serverCertPEM, serverKeyPEM, err := testCertAndKeyPEM(false)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	_, err = serverTLSConfig(serverCertPEM, serverKeyPEM, nil)
	if err == nil {
		t.Fatal("expected error for missing client CA")
	}
}

func TestServerTLSConfig_WithMTLS(t *testing.T) {
	serverCertPEM, serverKeyPEM, err := testCertAndKeyPEM(false)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	clientCAPEM, _, err := testCertAndKeyPEM(true)
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

func TestSignHandler_Success(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	service := &signer.Service{
		Store:       staticStore{signer: priv},
		AllowedSkew: 30 * time.Second,
	}
	h := signHandler(service)

	digest := sha256.Sum256([]byte("hello"))
	body, err := json.Marshal(signrpc.SignRequest{
		KeyID:         "relay-cert",
		Algorithm:     signrpc.AlgorithmRSAPKCS1v15SHA256,
		Digest:        digest[:],
		TimestampUnix: time.Now().Unix(),
		Nonce:         "abc",
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

	var resp signrpc.SignResponse
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
	body, err := json.Marshal(signrpc.SignRequest{
		KeyID:         "relay-cert",
		Algorithm:     signrpc.AlgorithmRSAPKCS1v15SHA256,
		Digest:        []byte{1},
		TimestampUnix: time.Now().Unix(),
		Nonce:         "abc",
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

func testCertAndKeyPEM(isCA bool) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "test.local",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tpl.IsCA = true
		tpl.KeyUsage |= x509.KeyUsageCertSign
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}
