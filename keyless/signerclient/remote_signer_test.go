package signerclient

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"keyless_tls/relay/signrpc"
)

func TestSignerTLSConfig_ServerAuthOnlyByDefault(t *testing.T) {
	rootCAPEM, _, err := testCertAndKeyPEM(true)
	if err != nil {
		t.Fatalf("create root CA cert: %v", err)
	}

	tlsConf, err := signerTLSConfig(RemoteSignerConfig{
		ServerName: "relay.internal",
		RootCAPEM:  rootCAPEM,
	})
	if err != nil {
		t.Fatalf("signerTLSConfig() error = %v", err)
	}
	if len(tlsConf.Certificates) != 0 {
		t.Fatalf("expected no client certificate, got %d", len(tlsConf.Certificates))
	}
}

func TestSignerTLSConfig_WithMTLS(t *testing.T) {
	rootCAPEM, _, err := testCertAndKeyPEM(true)
	if err != nil {
		t.Fatalf("create root CA cert: %v", err)
	}
	clientCertPEM, clientKeyPEM, err := testCertAndKeyPEM(false)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	tlsConf, err := signerTLSConfig(RemoteSignerConfig{
		ServerName:    "relay.internal",
		EnableMTLS:    true,
		RootCAPEM:     rootCAPEM,
		ClientCertPEM: clientCertPEM,
		ClientKeyPEM:  clientKeyPEM,
	})
	if err != nil {
		t.Fatalf("signerTLSConfig() error = %v", err)
	}
	if len(tlsConf.Certificates) != 1 {
		t.Fatalf("expected one client certificate, got %d", len(tlsConf.Certificates))
	}
}

func TestSignEndpoint_DefaultsToHTTPS(t *testing.T) {
	got := signEndpoint("127.0.0.1:9443")
	want := "https://127.0.0.1:9443" + signrpc.SignPath
	if got != want {
		t.Fatalf("signEndpoint() = %q, want %q", got, want)
	}
}

func TestSignEndpoint_WithScheme(t *testing.T) {
	got := signEndpoint("https://relay.internal:9443/")
	want := "https://relay.internal:9443" + signrpc.SignPath
	if got != want {
		t.Fatalf("signEndpoint() = %q, want %q", got, want)
	}
}

func TestRemoteSignerSign_HTTPJSON(t *testing.T) {
	serverCertPEM, serverKeyPEM, err := testCertAndKeyPEMWithCN("relay.internal", false)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(signrpc.SignPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			t.Fatalf("unexpected content-type: %s", r.Header.Get("Content-Type"))
		}

		var req signrpc.SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.KeyID != "relay-cert" {
			t.Fatalf("unexpected key id: %s", req.KeyID)
		}
		if req.Algorithm != signrpc.AlgorithmECDSASHA256 {
			t.Fatalf("unexpected algorithm: %s", req.Algorithm)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signrpc.SignResponse{
			KeyID:     req.KeyID,
			Algorithm: req.Algorithm,
			Signature: []byte("signed"),
		})
	})

	ts := httptest.NewUnstartedServer(mux)
	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("load server keypair: %v", err)
	}
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	ts.StartTLS()
	defer ts.Close()

	relayCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	rSigner, err := NewRemoteSigner(RemoteSignerConfig{
		Endpoint:   strings.TrimPrefix(ts.URL, "https://"),
		ServerName: "relay.internal",
		KeyID:      "relay-cert",
		RootCAPEM:  relayCertPEM,
		Timeout:    2 * time.Second,
	}, relayCertPEM)
	if err != nil {
		t.Fatalf("NewRemoteSigner() error = %v", err)
	}
	defer rSigner.Close()

	digest := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, digest); err != nil {
		t.Fatalf("random digest: %v", err)
	}

	sig, err := rSigner.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if string(sig) != "signed" {
		t.Fatalf("unexpected signature: %q", string(sig))
	}
}

func TestRemoteSignerSign_HTTPError(t *testing.T) {
	serverCertPEM, serverKeyPEM, err := testCertAndKeyPEMWithCN("relay.internal", false)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(signrpc.SignPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(signrpc.ErrorResponse{Error: "bad request"})
	})

	ts := httptest.NewUnstartedServer(mux)
	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("load server keypair: %v", err)
	}
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	ts.StartTLS()
	defer ts.Close()

	relayCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	rSigner, err := NewRemoteSigner(RemoteSignerConfig{
		Endpoint:   strings.TrimPrefix(ts.URL, "https://"),
		ServerName: "relay.internal",
		KeyID:      "relay-cert",
		RootCAPEM:  relayCertPEM,
		Timeout:    2 * time.Second,
	}, relayCertPEM)
	if err != nil {
		t.Fatalf("NewRemoteSigner() error = %v", err)
	}
	defer rSigner.Close()

	_, err = rSigner.Sign(rand.Reader, []byte{1, 2, 3}, crypto.SHA256)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "bad request") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func testCertAndKeyPEM(isCA bool) ([]byte, []byte, error) {
	return testCertAndKeyPEMWithCN("test.local", isCA)
}

func testCertAndKeyPEMWithCN(commonName string, isCA bool) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		DNSNames:              []string{commonName},
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
