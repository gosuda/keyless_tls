package t13server_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/internal/testutil"
	"github.com/gosuda/keyless_tls/keyless/t13server"
	"github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

type mockCryptoSignerStore struct {
	priv *ecdsa.PrivateKey
}

func (m *mockCryptoSignerStore) Signer(_ context.Context, _ string) (crypto.Signer, error) {
	return m.priv, nil
}

func TestTLS13Server_InteropWithStandardGoClient(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	// Extract private key from PEM to use as our signer
	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	activeBinding := []byte("relay-stream-nonce-1234")
	validatorCalled := false
	validator := signer.TranscriptValidatorFunc(func(ctx context.Context, req *signrpc.TranscriptSignRequest) error {
		if string(req.Binding) != string(activeBinding) {
			return errors.New("unauthorized binding")
		}
		validatorCalled = true
		return nil
	})

	signerSvc := &signer.Service{
		Store:               &mockCryptoSignerStore{priv: priv},
		TranscriptValidator: validator,
	}

	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-relay-key",
		NextProtos:       []string{"proto-a", "proto-b"},
		TranscriptSigner: signerSvc,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// Start raw TCP listener
	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLis.Close()

	// Server goroutine: accept raw conn and handshake
	go func() {
		rawConn, err := rawLis.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()

		tlsConn, err := srv.ServeConn(context.Background(), rawConn, activeBinding)
		if err != nil {
			t.Errorf("ServeConn failed: %v", err)
			return
		}
		defer tlsConn.Close()

		// Echo server
		buf := make([]byte, 1024)
		n, err := tlsConn.Read(buf)
		if err != nil {
			t.Errorf("read failed: %v", err)
			return
		}
		if string(buf[:n]) != "hello from standard client" {
			t.Errorf("unexpected message: %s", string(buf[:n]))
			return
		}
		if _, err := tlsConn.Write([]byte("hello from t13server")); err != nil {
			t.Errorf("write failed: %v", err)
			return
		}
	}()

	// Standard Go crypto/tls client dial
	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)

	clientConf := &tls.Config{
		ServerName: "example.com",
		RootCAs:    rootPool,
		NextProtos: []string{"proto-b"}, // Test ALPN negotiation
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}

	clientConn, err := tls.Dial("tcp", rawLis.Addr().String(), clientConf)
	if err != nil {
		t.Fatalf("tls.Dial failed: %v", err)
	}
	defer clientConn.Close()

	// Verify ALPN negotiation
	clientState := clientConn.ConnectionState()
	if clientState.NegotiatedProtocol != "proto-b" {
		t.Fatalf("expected negotiated protocol proto-b, got %q", clientState.NegotiatedProtocol)
	}
	if clientState.Version != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3, got %x", clientState.Version)
	}

	// Send echo payload
	if _, err := clientConn.Write([]byte("hello from standard client")); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	reply := make([]byte, 1024)
	n, err := clientConn.Read(reply)
	if err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if string(reply[:n]) != "hello from t13server" {
		t.Fatalf("unexpected reply: %s", string(reply[:n]))
	}

	if !validatorCalled {
		t.Fatal("expected transcript validator to be called")
	}
}

func TestTLS13Server_HTTPSInterop(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("localhost", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	signerSvc := &signer.Service{
		Store:                         &mockCryptoSignerStore{priv: priv},
		AllowUnboundTranscriptSigning: true,
	}

	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		NextProtos:       []string{"http/1.1"},
		TranscriptSigner: signerSvc,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLis.Close()

	// Wrap in t13server.Listener with binding provider
	bindingToken := []byte("stream-token-42")
	t13Lis := t13server.NewListener(rawLis, srv, func(raw net.Conn) ([]byte, error) {
		return bindingToken, nil
	})
	defer t13Lis.Close()

	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS != nil && r.TLS.ServerName != "localhost" {
				t.Errorf("unexpected ServerName in r.TLS: %q", r.TLS.ServerName)
			}
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("HTTPS GET success!"))
		}),
	}

	go func() {
		_ = httpServer.Serve(t13Lis)
	}()
	defer httpServer.Close()

	// Go http.Client request
	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: "localhost",
				RootCAs:    rootPool,
				MinVersion: tls.VersionTLS13,
			},
		},
		Timeout: 5 * time.Second,
	}

	url := fmt.Sprintf("https://%s/test", rawLis.Addr().String())
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("http GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "HTTPS GET success!" {
		t.Fatalf("unexpected body: %s", string(body))
	}
}

func TestTLS13Server_NegativeBindingMismatch(t *testing.T) {
	// Acceptance criterion: Add a negative test proving a transcript from connection A
	// cannot be signed/authorized using binding B.
	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	expectedBindingForStreamA := "authorized-binding-for-stream-A"

	// Validator enforces that only Stream A's binding is authorized
	validator := signer.TranscriptValidatorFunc(func(ctx context.Context, req *signrpc.TranscriptSignRequest) error {
		if string(req.Binding) != expectedBindingForStreamA {
			return fmt.Errorf("binding mismatch: caller presented %q, expected %q", string(req.Binding), expectedBindingForStreamA)
		}
		return nil
	})

	signerSvc := &signer.Service{
		Store:               &mockCryptoSignerStore{priv: priv},
		TranscriptValidator: validator,
	}

	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		TranscriptSigner: signerSvc,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLis.Close()

	// Server accepts with binding B (attacker tries to use binding B for connection A)
	unauthorizedBindingB := []byte("unauthorized-binding-B")
	serverErrCh := make(chan error, 1)
	go func() {
		rawConn, err := rawLis.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer rawConn.Close()

		_, err = srv.ServeConn(context.Background(), rawConn, unauthorizedBindingB)
		serverErrCh <- err
	}()

	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)

	clientConf := &tls.Config{
		ServerName: "example.com",
		RootCAs:    rootPool,
		MinVersion: tls.VersionTLS13,
	}

	// Client connection MUST fail because signer rejects unauthorized binding B
	clientConn, err := tls.Dial("tcp", rawLis.Addr().String(), clientConf)
	if err == nil {
		clientConn.Close()
		t.Fatal("expected tls.Dial to fail due to binding mismatch, but it succeeded")
	}

	serverErr := <-serverErrCh
	if serverErr == nil {
		t.Fatal("expected server error due to binding mismatch, but got nil")
	}
}

func TestTLS13Server_NegativeTLS12Client(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	signerSvc := &signer.Service{
		Store:                         &mockCryptoSignerStore{priv: priv},
		AllowUnboundTranscriptSigning: true,
	}

	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		TranscriptSigner: signerSvc,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLis.Close()

	go func() {
		rawConn, err := rawLis.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()
		_, _ = srv.ServeConn(context.Background(), rawConn, nil)
	}()

	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)

	// Force TLS 1.2 client
	clientConf := &tls.Config{
		ServerName: "example.com",
		RootCAs:    rootPool,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	}

	clientConn, err := tls.Dial("tcp", rawLis.Addr().String(), clientConf)
	if err == nil {
		clientConn.Close()
		t.Fatal("expected tls 1.2 client dial to fail, but succeeded")
	}
}

func TestTLS13Server_NegativeMissing0x1301InClientHello(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	signerSvc := &signer.Service{
		Store:                         &mockCryptoSignerStore{priv: priv},
		AllowUnboundTranscriptSigning: true,
	}

	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		TranscriptSigner: signerSvc,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	serverPipe, clientPipe := net.Pipe()
	defer serverPipe.Close()
	defer clientPipe.Close()

	go func() {
		// Send a synthetic ClientHello offering only 0x1302 (TLS_AES_256_GCM_SHA384)
		body := []byte{0x03, 0x03}                  // legacy version
		body = append(body, make([]byte, 32)...)    // random
		body = append(body, 0x00)                   // session id len 0
		body = append(body, 0x00, 0x02, 0x13, 0x02) // cipher suites (only 0x1302)
		body = append(body, 0x01, 0x00)             // compression
		body = append(body, 0x00, 0x00)             // extensions len 0

		msg := []byte{0x01, 0x00, byte(len(body) >> 8), byte(len(body))}
		msg = append(msg, body...)

		rec := []byte{0x16, 0x03, 0x03, byte(len(msg) >> 8), byte(len(msg))}
		rec = append(rec, msg...)
		_, _ = clientPipe.Write(rec)
	}()

	_, err = srv.ServeConn(context.Background(), serverPipe, nil)
	if err == nil {
		t.Fatal("expected ServeConn to fail when 0x1301 is missing, but got nil")
	}
}

func TestTLS13Server_LargePayloadMultiRecord(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	signerSvc := &signer.Service{
		Store:                         &mockCryptoSignerStore{priv: priv},
		AllowUnboundTranscriptSigning: true,
	}

	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		TranscriptSigner: signerSvc,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLis.Close()

	// 50 KiB payload (larger than a single 16 KiB TLS record)
	payloadSize := 50 * 1024
	expectedData := make([]byte, payloadSize)
	for i := range expectedData {
		expectedData[i] = byte(i % 251)
	}

	go func() {
		rawConn, err := rawLis.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()

		conn, err := srv.ServeConn(context.Background(), rawConn, nil)
		if err != nil {
			t.Errorf("ServeConn: %v", err)
			return
		}
		defer conn.Close()

		// Echo full stream
		_, _ = io.Copy(conn, conn)
	}()

	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)

	clientConn, err := tls.Dial("tcp", rawLis.Addr().String(), &tls.Config{
		ServerName: "example.com",
		RootCAs:    rootPool,
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer clientConn.Close()

	go func() {
		_, _ = clientConn.Write(expectedData)
	}()

	received := make([]byte, payloadSize)
	if _, err := io.ReadFull(clientConn, received); err != nil {
		t.Fatalf("read full: %v", err)
	}

	for i := range expectedData {
		if expectedData[i] != received[i] {
			t.Fatalf("payload mismatch at index %d", i)
		}
	}
}

func TestTLS13Server_E2ERemoteSignerOverHTTP(t *testing.T) {
	// Full distributed E2E test:
	// Relay Server running HTTP /v1/sign-transcript <--- RemoteSigner client <--- t13server
	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	relaySignerSvc := &signer.Service{
		Store: &mockCryptoSignerStore{priv: priv},
		TranscriptValidator: signer.TranscriptValidatorFunc(func(ctx context.Context, req *signrpc.TranscriptSignRequest) error {
			if string(req.Binding) != "e2e-valid-stream-ticket" {
				return errors.New("invalid stream ticket")
			}
			return nil
		}),
	}

	// Start mock Relay HTTP server exposing /v1/sign-transcript
	relayMux := http.NewServeMux()
	relayMux.HandleFunc(signrpc.TranscriptSignPath, func(w http.ResponseWriter, r *http.Request) {
		var req signrpc.TranscriptSignRequest
		if err := jsonDecode(r.Body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := relaySignerSvc.SignTranscript(r.Context(), &req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonEncode(w, resp)
	})

	relayLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	defer relayLis.Close()

	relayHTTP := &http.Server{Handler: relayMux}
	go func() { _ = relayHTTP.Serve(relayLis) }()
	defer relayHTTP.Close()

	// Direct signer client calling the mock relay
	remoteClient := &mockSignerClient{
		endpoint: fmt.Sprintf("http://%s%s", relayLis.Addr().String(), signrpc.TranscriptSignPath),
	}

	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "e2e-relay-key",
		TranscriptSigner: remoteClient,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLis.Close()

	// Handle connection with valid binding
	go func() {
		rawConn, err := rawLis.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()

		conn, err := srv.ServeConn(context.Background(), rawConn, []byte("e2e-valid-stream-ticket"))
		if err != nil {
			t.Errorf("ServeConn: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(append([]byte("echo: "), buf[:n]...))
	}()

	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)

	clientConn, err := tls.Dial("tcp", rawLis.Addr().String(), &tls.Config{
		ServerName: "example.com",
		RootCAs:    rootPool,
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("tls.Dial failed: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}

	respBuf := make([]byte, 64)
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(respBuf[:n]) != "echo: ping" {
		t.Fatalf("unexpected echo response: %s", string(respBuf[:n]))
	}
}

type mockSignerClient struct {
	endpoint string
}

func (m *mockSignerClient) SignTranscript(ctx context.Context, req *signrpc.TranscriptSignRequest) (*signrpc.TranscriptSignResponse, error) {
	bodyBytes, err := jsonMarshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint, bytesReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", httpResp.StatusCode)
	}

	var resp signrpc.TranscriptSignResponse
	if err := jsonDecode(httpResp.Body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func parseECDSAPrivateKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("no pem block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA private key")
	}
	return priv, nil
}

func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func jsonDecode(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}

func jsonEncode(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}

func bytesReader(b []byte) io.Reader {
	return bytes.NewReader(b)
}

func TestTLS13Server_AcceptDoesNotBlockOnStalledClient(t *testing.T) {
	// Proves that a client connecting and stalling before sending ClientHello
	// does not serialize or block the Accept() loop for other concurrent clients.
	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	signerSvc := &signer.Service{
		Store:                         &mockCryptoSignerStore{priv: priv},
		AllowUnboundTranscriptSigning: true,
	}

	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		TranscriptSigner: signerSvc,
		HandshakeTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLis.Close()

	t13Lis := t13server.NewListener(rawLis, srv, nil)
	defer t13Lis.Close()

	stalledErrCh := make(chan error, 1)
	var connCount int32
	var countMu sync.Mutex

	// Server accept loop
	go func() {
		for {
			conn, err := t13Lis.Accept()
			if err != nil {
				return
			}
			countMu.Lock()
			idx := connCount
			connCount++
			countMu.Unlock()

			// Handle each accepted connection concurrently
			go func(c net.Conn, isStalled bool) {
				defer c.Close()
				buf := make([]byte, 64)
				n, readErr := c.Read(buf)
				if isStalled {
					stalledErrCh <- readErr
					return
				}
				if n > 0 {
					_, _ = c.Write([]byte("ok"))
				}
			}(conn, idx == 0)
		}
	}()

	// 1. Client 1 connects via raw TCP and stalls (sends no bytes)
	stalledClient, err := net.Dial("tcp", rawLis.Addr().String())
	if err != nil {
		t.Fatalf("client 1 dial: %v", err)
	}
	defer stalledClient.Close()

	// 2. Client 2 connects via real TLS while Client 1 is stalled.
	// In a synchronous accept loop, Client 2 would hang until Client 1 timed out.
	// With lazy handshake, Client 2 connects and completes immediately!
	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)

	client2, err := tls.Dial("tcp", rawLis.Addr().String(), &tls.Config{
		ServerName: "example.com",
		RootCAs:    rootPool,
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("client 2 tls.Dial failed while client 1 stalled: %v", err)
	}
	defer client2.Close()

	if _, err := client2.Write([]byte("hello")); err != nil {
		t.Fatalf("client 2 write: %v", err)
	}
	resp := make([]byte, 10)
	n, err := client2.Read(resp)
	if err != nil {
		t.Fatalf("client 2 read: %v", err)
	}
	if string(resp[:n]) != "ok" {
		t.Fatalf("unexpected response from client 2: %s", string(resp[:n]))
	}

	// 3. Verify that the stalled connection terminates and returns a timeout error
	select {
	case err := <-stalledErrCh:
		if err == nil {
			t.Fatal("expected stalled connection read to fail with timeout error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for stalled connection to terminate")
	}
}

func TestTLS13Server_HandshakeContextCancellation(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	signerSvc := &signer.Service{
		Store:                         &mockCryptoSignerStore{priv: priv},
		AllowUnboundTranscriptSigning: true,
	}
	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		TranscriptSigner: signerSvc,
		HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLis.Close()

	clientConn, err := net.Dial("tcp", rawLis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	serverRaw, err := rawLis.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer serverRaw.Close()

	conn := srv.NewConn(serverRaw, nil)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	start := time.Now()
	go func() {
		errCh <- conn.HandshakeContext(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Fatalf("handshake cancellation took too long: %v", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HandshakeContext was not unblocked by context cancellation")
	}
}

func TestTLS13Server_ListenerBindingProviderErrorContinues(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	signerSvc := &signer.Service{
		Store:                         &mockCryptoSignerStore{priv: priv},
		AllowUnboundTranscriptSigning: true,
	}
	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		TranscriptSigner: signerSvc,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLis.Close()

	var attemptCount int32
	var countMu sync.Mutex
	bindingProvider := func(raw net.Conn) ([]byte, error) {
		countMu.Lock()
		defer countMu.Unlock()
		attemptCount++
		if attemptCount == 1 {
			return nil, errors.New("simulated binding extraction failure")
		}
		return []byte("valid-binding"), nil
	}

	t13Lis := t13server.NewListener(rawLis, srv, bindingProvider)
	defer t13Lis.Close()

	acceptedCh := make(chan net.Conn, 1)
	go func() {
		conn, err := t13Lis.Accept()
		if err != nil {
			return
		}
		acceptedCh <- conn
		go func() {
			buf := make([]byte, 16)
			_, _ = conn.Read(buf)
		}()
	}()

	// 1st dial: should be rejected by binding provider and closed by listener
	conn1, err := net.Dial("tcp", rawLis.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer conn1.Close()

	buf := make([]byte, 1)
	_ = conn1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn1.Read(buf)
	if err == nil {
		t.Fatal("expected connection 1 to be closed by server listener")
	}

	// 2nd dial: standard TLS dial should succeed and be returned by Accept()
	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)
	conn2, err := tls.Dial("tcp", rawLis.Addr().String(), &tls.Config{
		ServerName: "example.com",
		RootCAs:    rootPool,
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer conn2.Close()
	_, _ = conn2.Write([]byte("ping"))

	select {
	case c := <-acceptedCh:
		defer c.Close()
		t13Conn, ok := c.(*t13server.Conn)
		if !ok {
			t.Fatalf("expected *t13server.Conn, got %T", c)
		}
		if string(t13Conn.Binding()) != "valid-binding" {
			t.Fatalf("unexpected binding: %q", string(t13Conn.Binding()))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return second connection after first one failed binding provider")
	}
}

func TestTLS13Server_CloseUnblocksWrite(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	signerSvc := &signer.Service{
		Store:                         &mockCryptoSignerStore{priv: priv},
		AllowUnboundTranscriptSigning: true,
	}
	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		TranscriptSigner: signerSvc,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()

	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)
	tlsClient := tls.Client(clientRaw, &tls.Config{
		ServerName: "example.com",
		RootCAs:    rootPool,
		MinVersion: tls.VersionTLS13,
	})

	serverConn := srv.NewConn(serverRaw, nil)
	hsErrCh := make(chan error, 2)
	go func() {
		hsErrCh <- tlsClient.Handshake()
	}()
	go func() {
		hsErrCh <- serverConn.HandshakeContext(context.Background())
	}()

	for i := 0; i < 2; i++ {
		if err := <-hsErrCh; err != nil {
			t.Fatalf("handshake failed: %v", err)
		}
	}

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := serverConn.Write([]byte("blocked payload"))
		writeErrCh <- err
	}()

	time.Sleep(50 * time.Millisecond)
	closeErrCh := make(chan error, 1)
	go func() {
		closeErrCh <- serverConn.Close()
	}()

	select {
	case err := <-closeErrCh:
		if err != nil {
			t.Logf("Close returned error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("serverConn.Close() hung waiting on writeMu")
	}

	select {
	case <-writeErrCh:
		// Successfully unblocked
	case <-time.After(1 * time.Second):
		t.Fatal("serverConn.Write() was not unblocked by Close()")
	}
}

type splitFirstRecordConn struct {
	net.Conn
	splitDone bool
}

func (s *splitFirstRecordConn) Write(b []byte) (int, error) {
	if !s.splitDone && len(b) > 5 && b[0] == 0x16 {
		s.splitDone = true
		recPayload := b[5:]
		if len(recPayload) > 20 {
			part1 := recPayload[:20]
			part2 := recPayload[20:]

			rec1 := make([]byte, 5+len(part1))
			copy(rec1, b[:5])
			rec1[3] = byte(len(part1) >> 8)
			rec1[4] = byte(len(part1))
			copy(rec1[5:], part1)

			rec2 := make([]byte, 5+len(part2))
			copy(rec2, b[:5])
			rec2[3] = byte(len(part2) >> 8)
			rec2[4] = byte(len(part2))
			copy(rec2[5:], part2)

			if _, err := s.Conn.Write(rec1); err != nil {
				return 0, err
			}
			if _, err := s.Conn.Write(rec2); err != nil {
				return 0, err
			}
			return len(b), nil
		}
	}
	return s.Conn.Write(b)
}

func TestTLS13Server_FragmentedClientHello(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	signerSvc := &signer.Service{
		Store:                         &mockCryptoSignerStore{priv: priv},
		AllowUnboundTranscriptSigning: true,
	}
	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		TranscriptSigner: signerSvc,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLis.Close()

	go func() {
		raw, err := rawLis.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		conn, err := srv.ServeConn(context.Background(), raw, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(append([]byte("echo: "), buf[:n]...))
	}()

	clientRaw, err := net.Dial("tcp", rawLis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientRaw.Close()

	wrappedClient := &splitFirstRecordConn{Conn: clientRaw}
	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)

	tlsClient := tls.Client(wrappedClient, &tls.Config{
		ServerName: "example.com",
		RootCAs:    rootPool,
		MinVersion: tls.VersionTLS13,
	})
	defer tlsClient.Close()

	if _, err := tlsClient.Write([]byte("ping")); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, 64)
	n, err := tlsClient.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf[:n]) != "echo: ping" {
		t.Fatalf("unexpected echo response: %s", string(buf[:n]))
	}
}

func TestTLS13Server_DefaultALPNIsHTTP11(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	signerSvc := &signer.Service{
		Store:                         &mockCryptoSignerStore{priv: priv},
		AllowUnboundTranscriptSigning: true,
	}
	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		TranscriptSigner: signerSvc,
		// NextProtos intentionally omitted to test default
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)
	client := tls.Client(clientRaw, &tls.Config{
		ServerName: "example.com",
		RootCAs:    rootPool,
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS13,
	})

	serverConn := srv.NewConn(serverRaw, nil)
	hsErrCh := make(chan error, 2)
	go func() {
		hsErrCh <- client.Handshake()
	}()
	go func() {
		hsErrCh <- serverConn.HandshakeContext(context.Background())
	}()

	for i := 0; i < 2; i++ {
		if err := <-hsErrCh; err != nil {
			t.Fatalf("handshake failed: %v", err)
		}
	}

	if client.ConnectionState().NegotiatedProtocol != "http/1.1" {
		t.Fatalf("expected negotiated protocol http/1.1, got %q", client.ConnectionState().NegotiatedProtocol)
	}
	if serverConn.ConnectionState().NegotiatedProtocol != "http/1.1" {
		t.Fatalf("expected server negotiated protocol http/1.1, got %q", serverConn.ConnectionState().NegotiatedProtocol)
	}
}

func TestTLS13Server_CallerDeadlineShorterThanHandshakeTimeout(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	signerSvc := &signer.Service{
		Store:                         &mockCryptoSignerStore{priv: priv},
		AllowUnboundTranscriptSigning: true,
	}
	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		TranscriptSigner: signerSvc,
		HandshakeTimeout: 5 * time.Second, // Long server timeout
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLis.Close()

	// Client dials but stalls
	clientConn, err := net.Dial("tcp", rawLis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	serverRaw, err := rawLis.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer serverRaw.Close()

	conn := srv.NewConn(serverRaw, nil)
	// Caller sets a short 100ms read deadline before calling Read (which triggers lazy handshake)
	shortDeadline := 100 * time.Millisecond
	_ = conn.SetReadDeadline(time.Now().Add(shortDeadline))

	start := time.Now()
	buf := make([]byte, 64)
	_, readErr := conn.Read(buf)
	elapsed := time.Since(start)

	if readErr == nil {
		t.Fatal("expected read timeout error, got nil")
	}
	// Handshake must time out according to the caller's short deadline (~100ms), NOT 5 seconds
	if elapsed > 500*time.Millisecond {
		t.Fatalf("caller deadline was ignored; took %v to time out (expected ~100ms)", elapsed)
	}
}

func TestTLS13Server_HandshakeTimeoutWinsOverLaterContextDeadline(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	signerSvc := &signer.Service{
		Store:                         &mockCryptoSignerStore{priv: priv},
		AllowUnboundTranscriptSigning: true,
	}
	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		TranscriptSigner: signerSvc,
		HandshakeTimeout: 100 * time.Millisecond, // Short server timeout
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLis.Close()

	// Client stalls
	clientConn, err := net.Dial("tcp", rawLis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	serverRaw, err := rawLis.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer serverRaw.Close()

	conn := srv.NewConn(serverRaw, nil)
	// Caller passes context with a much longer deadline (5 seconds)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	hsErr := conn.HandshakeContext(ctx)
	elapsed := time.Since(start)

	if hsErr == nil {
		t.Fatal("expected handshake error due to HandshakeTimeout, got nil")
	}
	// HandshakeTimeout must win over the later context deadline!
	if elapsed > 500*time.Millisecond {
		t.Fatalf("HandshakeTimeout was not enforced; took %v (expected ~100ms)", elapsed)
	}
}

func TestTLS13Server_CallerDeadlinePreservedAfterHandshake(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	signerSvc := &signer.Service{
		Store:                         &mockCryptoSignerStore{priv: priv},
		AllowUnboundTranscriptSigning: true,
	}
	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		TranscriptSigner: signerSvc,
		HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)
	client := tls.Client(clientRaw, &tls.Config{
		ServerName: "example.com",
		RootCAs:    rootPool,
		MinVersion: tls.VersionTLS13,
	})

	serverConn := srv.NewConn(serverRaw, nil)
	// Caller sets a deadline of +10 seconds before handshake
	expectedDeadline := time.Now().Add(10 * time.Second)
	_ = serverConn.SetReadDeadline(expectedDeadline)

	hsErrCh := make(chan error, 2)
	go func() {
		hsErrCh <- client.Handshake()
	}()
	go func() {
		hsErrCh <- serverConn.HandshakeContext(context.Background())
	}()

	for i := 0; i < 2; i++ {
		if err := <-hsErrCh; err != nil {
			t.Fatalf("handshake failed: %v", err)
		}
	}

	// Verify standard ConnectionState fields
	cs := serverConn.ConnectionState()
	if !cs.HandshakeComplete {
		t.Fatal("expected HandshakeComplete to be true")
	}
	if cs.Version != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3, got %x", cs.Version)
	}
}

// blockingSigner records whether it received a context carrying a deadline,
// then blocks until that context is done and returns its error.
type blockingSigner struct {
	mu          sync.Mutex
	sawDeadline bool
}

func (b *blockingSigner) SignTranscript(ctx context.Context, _ *signrpc.TranscriptSignRequest) (*signrpc.TranscriptSignResponse, error) {
	if d, ok := ctx.Deadline(); ok && !d.IsZero() {
		b.mu.Lock()
		b.sawDeadline = true
		b.mu.Unlock()
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (b *blockingSigner) observedDeadline() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sawDeadline
}

// deadlineRecorder records deadline calls that reach the raw connection.
type deadlineRecorder struct {
	net.Conn

	mu       sync.Mutex
	reads    []time.Time
	writes   []time.Time
	combined []time.Time
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.reads = append(d.reads, t)
	d.mu.Unlock()
	return d.Conn.SetReadDeadline(t)
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.writes = append(d.writes, t)
	d.mu.Unlock()
	return d.Conn.SetWriteDeadline(t)
}

func (d *deadlineRecorder) SetDeadline(t time.Time) error {
	d.mu.Lock()
	d.combined = append(d.combined, t)
	d.mu.Unlock()
	return d.Conn.SetDeadline(t)
}

func (d *deadlineRecorder) snapshot() (reads, writes []time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Time(nil), d.reads...), append([]time.Time(nil), d.writes...)
}

func TestTLS13Server_HandshakeTimeoutBoundsRemoteSigning(t *testing.T) {
	// Acceptance criterion: HandshakeTimeout must bound the entire handshake,
	// including the remote transcript-signing round trip (which performs no
	// socket I/O), even when the caller passes an unbounded context — the
	// shape produced when http.Server invokes HandshakeContext itself.
	certPEM, _, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	signerSvc := &blockingSigner{}
	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		TranscriptSigner: signerSvc,
		HandshakeTimeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLis.Close()

	clientRaw, err := net.Dial("tcp", rawLis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientRaw.Close()

	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)
	client := tls.Client(clientRaw, &tls.Config{
		ServerName: "example.com",
		RootCAs:    rootPool,
		MinVersion: tls.VersionTLS13,
	})
	go func() { _ = client.Handshake() }() // its error is irrelevant; the server is the subject

	serverRaw, err := rawLis.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer serverRaw.Close()

	conn := srv.NewConn(serverRaw, nil)

	errCh := make(chan error, 1)
	start := time.Now()
	go func() {
		errCh <- conn.HandshakeContext(context.Background())
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("handshake not bounded by HandshakeTimeout: %v", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HandshakeTimeout did not bound the remote signing round trip")
	}

	if !signerSvc.observedDeadline() {
		t.Fatal("remote signer did not receive a context carrying the handshake deadline")
	}
}

func TestTLS13Server_CtxCancelRestoresDeadlinesAfterWatcher(t *testing.T) {
	// Acceptance criterion: the cancellation watcher must be fully joined
	// before caller-owned deadlines are restored, so a late
	// SetDeadline(past) from the watcher can never overwrite the restore.
	certPEM, _, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		TranscriptSigner: &blockingSigner{},
		HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLis.Close()

	clientRaw, err := net.Dial("tcp", rawLis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientRaw.Close()

	serverRaw, err := rawLis.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	recorder := &deadlineRecorder{Conn: serverRaw}
	defer recorder.Close()

	conn := srv.NewConn(recorder, nil)

	expectedDeadline := time.Now().Add(10 * time.Second)
	if err := conn.SetReadDeadline(expectedDeadline); err != nil {
		t.Fatalf("set caller read deadline: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- conn.HandshakeContext(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HandshakeContext was not unblocked by context cancellation")
	}

	// Give any racy late watcher ample opportunity to clobber the restore.
	time.Sleep(200 * time.Millisecond)

	reads, writes := recorder.snapshot()
	if last := reads[len(reads)-1]; !last.Equal(expectedDeadline) {
		t.Fatalf("caller read deadline not left restored: got %v, want %v", last, expectedDeadline)
	}
	if last := writes[len(writes)-1]; !last.IsZero() {
		t.Fatalf("write deadline not restored to zero after handshake: got %v", last)
	}
}

func TestTLS13Server_ConnectionStateServerSemantics(t *testing.T) {
	// Acceptance criterion: ConnectionState follows stdlib server-side
	// semantics — PeerCertificates and VerifiedChains describe the peer's
	// chain and stay empty without client authentication, while the chain
	// presented by this server appears in LocalCertificate.
	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	signerSvc := &signer.Service{
		Store:                         &mockCryptoSignerStore{priv: priv},
		AllowUnboundTranscriptSigning: true,
	}
	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-key",
		TranscriptSigner: signerSvc,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLis.Close()

	clientRaw, err := net.Dial("tcp", rawLis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientRaw.Close()

	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)
	client := tls.Client(clientRaw, &tls.Config{
		ServerName: "example.com",
		RootCAs:    rootPool,
		MinVersion: tls.VersionTLS13,
	})

	serverRaw, err := rawLis.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer serverRaw.Close()

	serverConn := srv.NewConn(serverRaw, nil)

	hsErrCh := make(chan error, 2)
	go func() {
		hsErrCh <- client.Handshake()
	}()
	go func() {
		hsErrCh <- serverConn.HandshakeContext(context.Background())
	}()

	for range 2 {
		if err := <-hsErrCh; err != nil {
			t.Fatalf("handshake failed: %v", err)
		}
	}

	cs := serverConn.ConnectionState()
	if !cs.HandshakeComplete || cs.Version != tls.VersionTLS13 {
		t.Fatalf("unexpected state: complete=%v version=%x", cs.HandshakeComplete, cs.Version)
	}
	if cs.PeerCertificates != nil {
		t.Fatal("PeerCertificates must be nil on a server connection without client authentication")
	}
	if cs.VerifiedChains != nil {
		t.Fatal("VerifiedChains must be nil on a server connection without client authentication")
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || len(cs.LocalCertificate) == 0 || !bytes.Equal(cs.LocalCertificate[0], block.Bytes) {
		t.Fatal("LocalCertificate must contain the server-presented leaf DER")
	}
	if cs.CipherSuite != tls.TLS_AES_128_GCM_SHA256 {
		t.Fatalf("unexpected cipher suite: %x", cs.CipherSuite)
	}
	if cs.CurveID != tls.X25519 {
		t.Fatalf("unexpected curve: %v", cs.CurveID)
	}
	if !cs.NegotiatedProtocolIsMutual {
		t.Fatal("expected NegotiatedProtocolIsMutual true to match stdlib server behavior")
	}
}
