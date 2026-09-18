package signerclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/internal/testutil"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

func TestSignerTLSConfig_WithMTLS(t *testing.T) {
	rootCAPEM, _, err := testutil.GenerateCert("test.local", true)
	if err != nil {
		t.Fatalf("create root CA cert: %v", err)
	}
	clientCertPEM, clientKeyPEM, err := testutil.GenerateCert("test.local", false)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	tlsConf, err := signerTLSConfig(RemoteSignerConfig{
		ServerName:    "relay.internal",
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
	if tlsConf.RootCAs == nil {
		t.Fatal("expected RootCAs to be set when mTLS is enabled")
	}
}

func TestSignerTLSConfig_WithoutMTLS(t *testing.T) {
	tlsConf, err := signerTLSConfig(RemoteSignerConfig{
		ServerName: "relay.internal",
	})
	if err != nil {
		t.Fatalf("signerTLSConfig() error = %v", err)
	}
	if len(tlsConf.Certificates) != 0 {
		t.Fatalf("expected no client certificates, got %d", len(tlsConf.Certificates))
	}
	if tlsConf.RootCAs != nil {
		t.Fatal("expected RootCAs to be nil (system pool) when no RootCAPEM provided")
	}
}

func TestSignerTLSConfig_PartialClientMaterial(t *testing.T) {
	clientCertPEM, clientKeyPEM, err := testutil.GenerateCert("test.local", false)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	// cert without key
	_, err = signerTLSConfig(RemoteSignerConfig{
		ServerName:    "relay.internal",
		ClientCertPEM: clientCertPEM,
	})
	if err == nil {
		t.Fatal("expected error when client cert is provided without key")
	}

	// key without cert
	_, err = signerTLSConfig(RemoteSignerConfig{
		ServerName:   "relay.internal",
		ClientKeyPEM: clientKeyPEM,
	})
	if err == nil {
		t.Fatal("expected error when client key is provided without cert")
	}
}

func TestSignerTLSConfig_InvalidRootCAPEM(t *testing.T) {
	_, err := signerTLSConfig(RemoteSignerConfig{
		ServerName: "relay.internal",
		RootCAPEM:  []byte("not-valid-pem"),
	})
	if err == nil {
		t.Fatal("expected error for invalid root CA PEM")
	}
}

func TestSignerTLSConfig_InvalidClientCertPEM(t *testing.T) {
	_, clientKeyPEM, err := testutil.GenerateCert("test.local", false)
	if err != nil {
		t.Fatalf("create client key: %v", err)
	}

	_, err = signerTLSConfig(RemoteSignerConfig{
		ServerName:    "relay.internal",
		ClientCertPEM: []byte("not-valid-cert"),
		ClientKeyPEM:  clientKeyPEM,
	})
	if err == nil {
		t.Fatal("expected error for invalid client cert PEM")
	}
}

func TestNewRemoteSigner_RequiresServerName(t *testing.T) {
	rootCAPEM, _, err := testutil.GenerateCert("test.local", true)
	if err != nil {
		t.Fatalf("create root CA cert: %v", err)
	}
	clientCertPEM, clientKeyPEM, err := testutil.GenerateCert("test.local", false)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	_, err = NewRemoteSigner(RemoteSignerConfig{
		Endpoint:      "relay.internal:9443",
		KeyID:         "relay-cert",
		RootCAPEM:     rootCAPEM,
		ClientCertPEM: clientCertPEM,
		ClientKeyPEM:  clientKeyPEM,
	})
	if err == nil {
		t.Fatal("expected NewRemoteSigner to require server name")
	}
}

func TestNewRemoteSigner_WithoutMTLS(t *testing.T) {
	rs, err := NewRemoteSigner(RemoteSignerConfig{
		Endpoint:   "relay.internal:9443",
		ServerName: "relay.internal",
		KeyID:      "relay-cert",
	})
	if err != nil {
		t.Fatalf("NewRemoteSigner() error = %v", err)
	}
	defer rs.Close()
}

func TestRemoteSignerSignTranscript_RejectsConfiguredKeyIDMismatch(t *testing.T) {
	rSigner := &RemoteSigner{keyID: "relay-cert"}

	_, err := rSigner.SignTranscript(context.Background(), &signrpc.TranscriptSignRequest{
		KeyID:     "other-key",
		Algorithm: signrpc.AlgorithmECDSASHA256,
	})
	if err == nil {
		t.Fatal("expected key ID mismatch error")
	}
	if !strings.Contains(err.Error(), "sign request key ID mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSignEndpoint_DefaultsToHTTPS(t *testing.T) {
	got, err := signEndpoint("127.0.0.1:9443")
	if err != nil {
		t.Fatalf("signEndpoint() error = %v", err)
	}
	want := "https://127.0.0.1:9443" + signrpc.SignPath
	if got != want {
		t.Fatalf("signEndpoint() = %q, want %q", got, want)
	}
}

func TestSignEndpoint_WithScheme(t *testing.T) {
	got, err := signEndpoint("https://relay.internal:9443/")
	if err != nil {
		t.Fatalf("signEndpoint() error = %v", err)
	}
	want := "https://relay.internal:9443" + signrpc.SignPath
	if got != want {
		t.Fatalf("signEndpoint() = %q, want %q", got, want)
	}
}

func TestSignEndpoint_RejectsNonHTTPS(t *testing.T) {
	_, err := signEndpoint("http://127.0.0.1:9443")
	if err == nil {
		t.Fatal("expected signEndpoint to reject non-https endpoint")
	}
}

func TestSignEndpoint_RejectsPath(t *testing.T) {
	_, err := signEndpoint("https://relay.internal:9443/v1/sign")
	if err == nil {
		t.Fatal("expected signEndpoint to reject endpoint with path")
	}

	_, err = signEndpoint("relay.internal:9443/v1/sign")
	if err == nil {
		t.Fatal("expected signEndpoint to reject endpoint with path")
	}
}

func TestSignEndpoint_RejectsQueryOrFragment(t *testing.T) {
	_, err := signEndpoint("https://relay.internal:9443?x=1")
	if err == nil {
		t.Fatal("expected signEndpoint to reject query")
	}
}

func TestRemoteSignerSignTranscript_HTTPJSON(t *testing.T) {
	serverCertPEM, serverKeyPEM, err := testutil.GenerateCert("relay.internal", false)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	clientCertPEM, clientKeyPEM, err := testutil.GenerateCert("test.local", false)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(signrpc.SignPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			t.Fatalf("unexpected content-type: %s", r.Header.Get("Content-Type"))
		}

		var req signrpc.TranscriptSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.KeyID != "relay-cert" {
			t.Fatalf("unexpected key id: %s", req.KeyID)
		}
		if req.Nonce == "" {
			t.Fatal("expected client to fill nonce")
		}
		if req.TimestampUnix == 0 {
			t.Fatal("expected client to fill timestamp")
		}
		if len(req.ClientHello) == 0 || len(req.ServerHello) == 0 || len(req.EncryptedExtensions) == 0 || len(req.Certificate) == 0 {
			t.Fatal("expected transcript fields in request")
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signrpc.TranscriptSignResponse{
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
		Endpoint:      strings.TrimPrefix(ts.URL, "https://"),
		ServerName:    "relay.internal",
		KeyID:         "relay-cert",
		RootCAPEM:     relayCertPEM,
		ClientCertPEM: clientCertPEM,
		ClientKeyPEM:  clientKeyPEM,
		Timeout:       2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewRemoteSigner() error = %v", err)
	}
	defer rSigner.Close()

	resp, err := rSigner.SignTranscript(context.Background(), &signrpc.TranscriptSignRequest{
		Algorithm:           signrpc.AlgorithmECDSASHA256,
		Binding:             []byte{0x01},
		ClientHello:         []byte("client-hello"),
		ServerHello:         []byte("server-hello"),
		EncryptedExtensions: []byte("encrypted-extensions"),
		Certificate:         []byte("certificate"),
	})
	if err != nil {
		t.Fatalf("SignTranscript() error = %v", err)
	}
	if string(resp.Signature) != "signed" {
		t.Fatalf("unexpected signature: %q", string(resp.Signature))
	}
}

func TestRemoteSignerSignTranscript_DynamicHeaders(t *testing.T) {
	serverCertPEM, serverKeyPEM, err := testutil.GenerateCert("relay.internal", false)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	var headerCalls atomic.Int32
	var requests atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc(signrpc.SignPath, func(w http.ResponseWriter, r *http.Request) {
		expected := fmt.Sprintf("token-%d", requests.Add(1))
		if got := r.Header.Get("X-Portal-Access-Token"); got != expected {
			t.Fatalf("unexpected access token: %q, want %q", got, expected)
		}

		var req signrpc.TranscriptSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signrpc.TranscriptSignResponse{
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
		Headers: func() http.Header {
			token := fmt.Sprintf("token-%d", headerCalls.Add(1))
			return http.Header{"X-Portal-Access-Token": []string{token}}
		},
	})
	if err != nil {
		t.Fatalf("NewRemoteSigner() error = %v", err)
	}
	defer rSigner.Close()

	transcriptReq := &signrpc.TranscriptSignRequest{
		Algorithm:           signrpc.AlgorithmECDSASHA256,
		Binding:             []byte{0x01},
		ClientHello:         []byte("client-hello"),
		ServerHello:         []byte("server-hello"),
		EncryptedExtensions: []byte("encrypted-extensions"),
		Certificate:         []byte("certificate"),
	}
	for range 2 {
		if _, err := rSigner.SignTranscript(context.Background(), transcriptReq); err != nil {
			t.Fatalf("SignTranscript() error = %v", err)
		}
	}
	if got := headerCalls.Load(); got != 2 {
		t.Fatalf("header callback calls = %d, want 2", got)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
}

func TestRemoteSignerSignTranscript_HTTPError(t *testing.T) {
	serverCertPEM, serverKeyPEM, err := testutil.GenerateCert("relay.internal", false)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	clientCertPEM, clientKeyPEM, err := testutil.GenerateCert("test.local", false)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
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
		Endpoint:      strings.TrimPrefix(ts.URL, "https://"),
		ServerName:    "relay.internal",
		KeyID:         "relay-cert",
		RootCAPEM:     relayCertPEM,
		ClientCertPEM: clientCertPEM,
		ClientKeyPEM:  clientKeyPEM,
		Timeout:       2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewRemoteSigner() error = %v", err)
	}
	defer rSigner.Close()

	_, err = rSigner.SignTranscript(context.Background(), &signrpc.TranscriptSignRequest{
		Algorithm:           signrpc.AlgorithmECDSASHA256,
		Binding:             []byte{0x01},
		ClientHello:         []byte("client-hello"),
		ServerHello:         []byte("server-hello"),
		EncryptedExtensions: []byte("encrypted-extensions"),
		Certificate:         []byte("certificate"),
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "bad request") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRemoteSignerSignTranscript_ResponseValidation(t *testing.T) {
	serverCertPEM, serverKeyPEM, err := testutil.GenerateCert("relay.internal", false)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	tests := []struct {
		name    string
		resp    signrpc.TranscriptSignResponse
		wantErr string
	}{
		{
			name: "key id mismatch",
			resp: signrpc.TranscriptSignResponse{
				KeyID:     "wrong-key",
				Algorithm: signrpc.AlgorithmECDSASHA256,
				Signature: []byte("sig"),
			},
			wantErr: "key ID mismatch",
		},
		{
			name: "algorithm mismatch",
			resp: signrpc.TranscriptSignResponse{
				KeyID:     "relay-cert",
				Algorithm: signrpc.AlgorithmRSAPSSSHA256,
				Signature: []byte("sig"),
			},
			wantErr: "algorithm mismatch",
		},
		{
			name: "empty signature",
			resp: signrpc.TranscriptSignResponse{
				KeyID:     "relay-cert",
				Algorithm: signrpc.AlgorithmECDSASHA256,
				Signature: nil,
			},
			wantErr: "signature is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc(signrpc.SignPath, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.resp)
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
			})
			if err != nil {
				t.Fatalf("NewRemoteSigner() error = %v", err)
			}
			defer rSigner.Close()

			_, err = rSigner.SignTranscript(context.Background(), &signrpc.TranscriptSignRequest{
				KeyID:               "relay-cert",
				Algorithm:           signrpc.AlgorithmECDSASHA256,
				Binding:             []byte{0x01},
				ClientHello:         []byte("client-hello"),
				ServerHello:         []byte("server-hello"),
				EncryptedExtensions: []byte("encrypted-extensions"),
				Certificate:         []byte("certificate"),
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}
