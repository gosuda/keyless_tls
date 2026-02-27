package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestServerTLSConfig_NoMTLS(t *testing.T) {
	serverCertPEM, serverKeyPEM, err := testCertAndKeyPEM(false)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	tlsConf, err := serverTLSConfig(serverCertPEM, serverKeyPEM, nil, false)
	if err != nil {
		t.Fatalf("serverTLSConfig() error = %v", err)
	}
	if tlsConf.ClientAuth != tls.NoClientCert {
		t.Fatalf("expected ClientAuth=%v, got %v", tls.NoClientCert, tlsConf.ClientAuth)
	}
	if tlsConf.ClientCAs != nil {
		t.Fatal("expected ClientCAs to be nil when mTLS disabled")
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

	tlsConf, err := serverTLSConfig(serverCertPEM, serverKeyPEM, clientCAPEM, true)
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

func TestServerTLSConfig_WithMTLSRequiresClientCA(t *testing.T) {
	serverCertPEM, serverKeyPEM, err := testCertAndKeyPEM(false)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	_, err = serverTLSConfig(serverCertPEM, serverKeyPEM, nil, true)
	if err == nil {
		t.Fatal("expected error for missing client CA")
	}
	if !strings.Contains(err.Error(), "failed to parse client CA PEM") {
		t.Fatalf("unexpected error: %v", err)
	}
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
