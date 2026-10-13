package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/internal/admission"
	"github.com/gosuda/keyless_tls/internal/testutil"
	"github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

func TestSigningAdmissionReleasesStalledBody(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("signer.test", false)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, caKeyPEM, err := testutil.GenerateCert("client.test", true)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := serverTLSConfig(certPEM, keyPEM, caPEM, false)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	clientTLS := &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: "signer.test", RootCAs: roots,
		Certificates: []tls.Certificate{signedClientCertificate(t, caPEM, caKeyPEM)},
	}
	limits, err := (Limits{ReadTimeout: time.Second}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	handler := signHandlerWithLimits(&signer.Service{Store: staticStore{signer: mustRSAKey(t)}},
		admission.Limits{MaxConcurrent: 2, MaxPerIdentity: 1, MaxIdentities: 2})
	go func() { done <- serve(ctx, lis, serverTLS, handler, limits) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("server shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not shut down")
		}
	})
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", lis.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = io.WriteString(conn, "POST /v1/sign HTTP/1.1\r\nHost: signer.test\r\nContent-Type: application/json\r\nContent-Length: 500\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	interim, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	interim.Body.Close()
	if interim.StatusCode != http.StatusContinue {
		t.Fatalf("stalled request was not admitted: HTTP %d", interim.StatusCode)
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: clientTLS}}
	defer client.CloseIdleConnections()
	send := func(want int) {
		t.Helper()
		resp, err := client.Post("https://"+lis.Addr().String()+signrpc.SignPath, "application/json", bytes.NewReader(validSignBody(t)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("signing status = %d, want %d", resp.StatusCode, want)
		}
	}
	send(http.StatusTooManyRequests)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("stalled request did not receive its timeout response: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("stalled request status = %d, want 400", response.StatusCode)
	}
	send(http.StatusOK)
}

func TestClientConcurrencyAboveDefaultAggregateLimit(t *testing.T) {
	limiter := admission.New(clientLimits(Config{
		MaxConcurrentRequestsPerClient: 256, RequestsPerClientPerSecond: 1000, ClientBurst: 1000,
	}))
	for i := 0; i < 256; i++ {
		if !limiter.TryAcquire("client") {
			t.Fatalf("configured concurrency rejected request %d", i+1)
		}
	}
	if limiter.TryAcquire("client") {
		t.Fatal("per-client concurrency limit was exceeded")
	}
	for range 256 {
		limiter.Release("client")
	}
}
