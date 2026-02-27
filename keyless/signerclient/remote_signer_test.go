package signerclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
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
