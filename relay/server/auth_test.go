package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/internal/testutil"
	"github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

func TestListenAndServeRequiresClientCA(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("test.local", false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{ListenAddr: "127.0.0.1:0", ServerCertPEM: certPEM, ServerKeyPEM: keyPEM, SignerService: &signer.Service{}}
	if err := ListenAndServe(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "client CA PEM is required") {
		t.Fatalf("expected startup to reject missing client CA, got %v", err)
	}
}

func TestSignEndpointRejectsUnauthenticatedClient(t *testing.T) {
	serverCertPEM, serverKeyPEM, err := testutil.GenerateCert("test.local", false)
	if err != nil {
		t.Fatal(err)
	}
	clientCAPEM, clientCAKeyPEM, err := testutil.GenerateCert("client-ca.local", true)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := serverTLSConfig(serverCertPEM, serverKeyPEM, clientCAPEM, false)
	if err != nil {
		t.Fatalf("serverTLSConfig(): %v", err)
	}

	server := httptest.NewUnstartedServer(signHandler(&signer.Service{}))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(serverCertPEM) {
		t.Fatal("failed to trust server certificate")
	}
	clientCert := signedClientCertificate(t, clientCAPEM, clientCAKeyPEM)
	clientTLS := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		ServerName:   "test.local",
		Certificates: []tls.Certificate{clientCert},
	}
	trustedClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: clientTLS}}
	defer trustedClient.CloseIdleConnections()
	resp, err := trustedClient.Post(server.URL+signrpc.SignPath, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("trusted client should complete TLS handshake: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("trusted client: status=%d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	unauthenticatedTLS := clientTLS.Clone()
	unauthenticatedTLS.Certificates = nil
	unauthenticatedClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: unauthenticatedTLS}}
	defer unauthenticatedClient.CloseIdleConnections()
	resp, err = unauthenticatedClient.Post(server.URL+signrpc.SignPath, "application/json", strings.NewReader("{}"))
	if err == nil {
		resp.Body.Close()
		t.Fatalf("unauthenticated client reached /v1/sign: HTTP %d", resp.StatusCode)
	}
}

// signedClientCertificate issues a client-auth leaf from the test CA.
func signedClientCertificate(t *testing.T, caPEM, keyPEM []byte) tls.Certificate {
	t.Helper()
	certBlock, _ := pem.Decode(caPEM)
	if certBlock == nil {
		t.Fatal("decode client CA certificate")
	}
	ca, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parse client CA certificate: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("decode client CA key")
	}
	caKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse client CA key: %v", err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	now := time.Now()
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign client certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: clientKey}
}
