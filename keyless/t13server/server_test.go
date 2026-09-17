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
		body = append(body, make([]byte, 32)...)   // random
		body = append(body, 0x00)                  // session id len 0
		body = append(body, 0x00, 0x02, 0x13, 0x02) // cipher suites (only 0x1302)
		body = append(body, 0x01, 0x00)            // compression
		body = append(body, 0x00, 0x00)            // extensions len 0

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

	// Server accept loop
	acceptedConns := make(chan net.Conn, 10)
	go func() {
		for {
			conn, err := t13Lis.Accept()
			if err != nil {
				return
			}
			acceptedConns <- conn
			// Handle each accepted connection concurrently
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write([]byte("ok"))
				}
			}(conn)
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
}

