package keyless

import (
	"crypto/tls"
	"testing"

	"github.com/gosuda/keyless_tls/internal/testutil"
)

func TestNewClientTLSConfig_WithMTLS(t *testing.T) {
	rootCAPEM, _, err := testutil.GenerateCert("test.local", true)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}
	clientCertPEM, clientKeyPEM, err := testutil.GenerateCert("test.local", false)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	tlsConf, err := NewClientTLSConfig(clientCertPEM, clientKeyPEM, rootCAPEM, "test.local")
	if err != nil {
		t.Fatalf("NewClientTLSConfig() error = %v", err)
	}
	if len(tlsConf.Certificates) != 1 {
		t.Fatalf("expected 1 client certificate, got %d", len(tlsConf.Certificates))
	}
	if tlsConf.RootCAs == nil {
		t.Fatal("expected RootCAs to be set")
	}
	if tlsConf.ServerName != "test.local" {
		t.Fatalf("expected ServerName=%q, got %q", "test.local", tlsConf.ServerName)
	}
	if tlsConf.MinVersion != tls.VersionTLS13 {
		t.Fatalf("expected MinVersion=TLS13, got %d", tlsConf.MinVersion)
	}
}

func TestNewClientTLSConfig_WithoutMTLS(t *testing.T) {
	tlsConf, err := NewClientTLSConfig(nil, nil, nil, "test.local")
	if err != nil {
		t.Fatalf("NewClientTLSConfig() error = %v", err)
	}
	if len(tlsConf.Certificates) != 0 {
		t.Fatalf("expected no client certificates, got %d", len(tlsConf.Certificates))
	}
	if tlsConf.RootCAs != nil {
		t.Fatal("expected nil RootCAs (system pool)")
	}
}

func TestNewClientTLSConfig_PartialClientMaterial(t *testing.T) {
	clientCertPEM, clientKeyPEM, err := testutil.GenerateCert("test.local", false)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	_, err = NewClientTLSConfig(clientCertPEM, nil, nil, "test.local")
	if err == nil {
		t.Fatal("expected error for cert without key")
	}

	_, err = NewClientTLSConfig(nil, clientKeyPEM, nil, "test.local")
	if err == nil {
		t.Fatal("expected error for key without cert")
	}
}

func TestNewClientTLSConfig_InvalidRootCAPEM(t *testing.T) {
	_, err := NewClientTLSConfig(nil, nil, []byte("not-valid-pem"), "test.local")
	if err == nil {
		t.Fatal("expected error for invalid root CA PEM")
	}
}

func TestNewClientTLSConfig_EmptyServerName(t *testing.T) {
	tlsConf, err := NewClientTLSConfig(nil, nil, nil, "")
	if err != nil {
		t.Fatalf("NewClientTLSConfig() error = %v", err)
	}
	if tlsConf.ServerName != "" {
		t.Fatalf("expected empty ServerName, got %q", tlsConf.ServerName)
	}
}

