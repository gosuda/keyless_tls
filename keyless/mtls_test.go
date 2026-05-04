package keyless

import (
	"crypto/tls"
	"errors"
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

func TestNewClientTLSConfigWithOptions_ECH(t *testing.T) {
	echConfigList := []byte{0x00, 0x02, 0xfe, 0x0d}
	verify := func(tls.ConnectionState) error { return nil }

	tlsConf, err := NewClientTLSConfigWithOptions(ClientTLSConfigOptions{
		ServerName:                          "inner.example.com",
		EncryptedClientHelloConfigList:      echConfigList,
		EncryptedClientHelloRejectionVerify: verify,
	})
	if err != nil {
		t.Fatalf("NewClientTLSConfigWithOptions() error = %v", err)
	}
	if string(tlsConf.EncryptedClientHelloConfigList) != string(echConfigList) {
		t.Fatalf("ECH config list = %x, want %x", tlsConf.EncryptedClientHelloConfigList, echConfigList)
	}
	if tlsConf.EncryptedClientHelloRejectionVerify == nil {
		t.Fatal("expected ECH rejection verifier to be set")
	}
}

func TestShouldFallbackFromECH(t *testing.T) {
	tlsConf := &tls.Config{EncryptedClientHelloConfigList: []byte{0xfe, 0x0d}}

	if !shouldFallbackFromECH(&tls.ECHRejectionError{}, tlsConf, true) {
		t.Fatal("expected fallback for ECH rejection when explicitly allowed")
	}
	if shouldFallbackFromECH(&tls.ECHRejectionError{}, tlsConf, false) {
		t.Fatal("fallback should require explicit opt-in")
	}
	if shouldFallbackFromECH(errors.New("handshake failed"), tlsConf, true) {
		t.Fatal("fallback should only apply to ECH rejection errors")
	}
}

func TestCloneWithoutECH(t *testing.T) {
	tlsConf := &tls.Config{
		ServerName:                          "inner.example.com",
		EncryptedClientHelloConfigList:      []byte{0xfe, 0x0d},
		EncryptedClientHelloRejectionVerify: func(tls.ConnectionState) error { return nil },
	}

	clone := cloneWithoutECH(tlsConf)
	if clone == tlsConf {
		t.Fatal("expected TLS config clone")
	}
	if len(clone.EncryptedClientHelloConfigList) != 0 {
		t.Fatal("expected fallback config to clear ECH config list")
	}
	if clone.EncryptedClientHelloRejectionVerify != nil {
		t.Fatal("expected fallback config to clear ECH rejection verifier")
	}
	if clone.ServerName != tlsConf.ServerName {
		t.Fatalf("ServerName = %q, want %q", clone.ServerName, tlsConf.ServerName)
	}
}
