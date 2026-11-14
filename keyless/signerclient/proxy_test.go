package signerclient_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/internal/testutil"
	"github.com/gosuda/keyless_tls/keyless/signerclient"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

func TestRemoteSignerEnvironmentProxy(t *testing.T) {
	// ProxyFromEnvironment caches the environment on first use. Each scenario
	// needs a fresh process to exercise the production policy independently.
	scenario := os.Getenv("KEYLESS_SIGNER_PROXY_SCENARIO")
	if scenario == "" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{
			"proxy", "direct", "no_proxy", "wrong_server_name",
			"untrusted_server", "missing_client_cert", "untrusted_client_cert",
		} {
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, binary, "-test.run=^TestRemoteSignerEnvironmentProxy$", "-test.v", "-test.timeout=20s")
				cmd.Env = append(os.Environ(), "KEYLESS_SIGNER_PROXY_SCENARIO="+name)
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("%v\n%s", err, output)
				}
				t.Logf("%s", output)
			})
		}
		return
	}

	for _, key := range []string{
		"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
		"NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy", "REQUEST_METHOD",
	} {
		t.Setenv(key, "")
	}

	serverPEM, serverKey, err := testutil.GenerateCert("relay.internal", false)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.X509KeyPair(serverPEM, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clientPEM, clientKey, err := testutil.GenerateCert("client.internal", false)
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(clientPEM) {
		t.Fatal("load trusted client certificate")
	}

	var signed atomic.Bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != signrpc.SignPath {
			t.Errorf("unexpected signing request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if r.TLS.Version != tls.VersionTLS13 || r.TLS.ServerName != "relay.internal" || len(r.TLS.VerifiedChains) == 0 {
			t.Error("signing request did not use authenticated TLS 1.3 with the configured server name")
			http.Error(w, "unexpected TLS state", http.StatusBadRequest)
			return
		}
		var req signrpc.TranscriptSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode signing request: %v", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		signed.Store(true)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signrpc.TranscriptSignResponse{
			KeyID: req.KeyID, Algorithm: req.Algorithm, Signature: []byte("signed"),
		})
	}))
	if scenario == "no_proxy" {
		// Go always bypasses proxies for loopback addresses, so use a real
		// interface address to ensure NO_PROXY is what enables direct access.
		addresses, err := net.InterfaceAddrs()
		if err != nil {
			t.Fatal(err)
		}
		var listener net.Listener
		for _, addr := range addresses {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil || ip.To4() == nil || ip.IsLoopback() || !ip.IsGlobalUnicast() {
				continue
			}
			listener, err = net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
			if err == nil {
				break
			}
		}
		if listener == nil {
			server.Close()
			t.Skip("NO_PROXY signing test requires a non-loopback IPv4 interface")
		}
		_ = server.Listener.Close()
		server.Listener = listener
	}
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
	}
	server.StartTLS()
	defer server.Close()

	var proxied atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Store(true)
		if r.Method != http.MethodConnect || r.Host != "signer.invalid:443" {
			t.Errorf("unexpected proxy request: %s %s", r.Method, r.Host)
			http.Error(w, "unexpected CONNECT", http.StatusBadGateway)
			return
		}
		upstream, err := net.DialTimeout("tcp", server.Listener.Addr().String(), 5*time.Second)
		if err != nil {
			t.Errorf("connect proxy upstream: %v", err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack CONNECT: %v", err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		_ = upstream.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(upstream, buffered)
			_ = upstream.Close()
			close(done)
		}()
		_, _ = io.Copy(conn, upstream)
		_ = conn.Close()
		<-done
	}))
	defer proxy.Close()

	cfg := signerclient.RemoteSignerConfig{
		Endpoint: "https://signer.invalid:443", ServerName: "relay.internal", KeyID: "relay-cert",
		RootCAPEM: serverPEM, ClientCertPEM: clientPEM, ClientKeyPEM: clientKey,
		Timeout: 5 * time.Second,
	}
	t.Setenv("HTTPS_PROXY", proxy.URL)
	wantProxy := true
	wantErr := false
	switch scenario {
	case "proxy":
	case "direct":
		cfg.Endpoint = server.URL
		t.Setenv("HTTPS_PROXY", "")
		wantProxy = false
	case "no_proxy":
		cfg.Endpoint = server.URL
		host, _, err := net.SplitHostPort(server.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("NO_PROXY", host)
		wantProxy = false
	case "wrong_server_name":
		cfg.ServerName = "wrong.internal"
		wantErr = true
	case "untrusted_server":
		cfg.RootCAPEM = clientPEM
		wantErr = true
	case "missing_client_cert":
		cfg.ClientCertPEM, cfg.ClientKeyPEM = nil, nil
		wantErr = true
	case "untrusted_client_cert":
		cfg.ClientCertPEM, cfg.ClientKeyPEM = serverPEM, serverKey
		wantErr = true
	default:
		t.Fatalf("unknown scenario: %s", scenario)
	}

	signer, err := signerclient.NewRemoteSigner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	resp, err := signer.SignTranscript(context.Background(), &signrpc.TranscriptSignRequest{
		Algorithm:   signrpc.AlgorithmECDSASHA256,
		ClientHello: []byte("client-hello"), ServerHello: []byte("server-hello"),
		EncryptedExtensions: []byte("encrypted-extensions"), Certificate: []byte("certificate"),
	})
	if wantErr {
		if err == nil || !strings.Contains(err.Error(), "tls:") {
			t.Fatalf("expected TLS authentication failure, got response %v, error %v", resp, err)
		}
		if signed.Load() {
			t.Error("unauthenticated request reached signing endpoint")
		}
	} else if err != nil {
		t.Fatalf("SignTranscript: %v", err)
	} else if !signed.Load() || string(resp.Signature) != "signed" {
		t.Fatalf("unexpected signing response: %v", resp)
	}
	if got := proxied.Load(); got != wantProxy {
		t.Errorf("request used proxy = %v, want %v", got, wantProxy)
	}
}
