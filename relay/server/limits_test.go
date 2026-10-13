package server

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/relay/signer"
)

func TestLimitsDefaults(t *testing.T) {
	limits, err := (Limits{}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if limits.ReadHeaderTimeout != 5*time.Second || limits.ReadTimeout != 10*time.Second || limits.WriteTimeout != 15*time.Second || limits.IdleTimeout != 30*time.Second {
		t.Fatalf("unexpected timeout defaults: %+v", limits)
	}
	if limits.MaxHeaderBytes != 16<<10 || limits.MaxConnections != 256 || limits.MaxConnectionsPerIP != 64 {
		t.Fatalf("unexpected size and connection defaults: %+v", limits)
	}
}

func TestLimitsRejectNegativeValues(t *testing.T) {
	cases := []Limits{
		{ReadHeaderTimeout: -1},
		{ReadTimeout: -1},
		{WriteTimeout: -1},
		{IdleTimeout: -1},
		{MaxHeaderBytes: -1},
		{MaxConnections: -1},
		{MaxConnectionsPerIP: -1},
	}
	for _, cfg := range cases {
		if _, err := cfg.withDefaults(); err == nil {
			t.Errorf("expected error for %+v", cfg)
		}
	}
}

func TestLimitsPreserveOverrides(t *testing.T) {
	cfg := Limits{ReadHeaderTimeout: 1 * time.Second, MaxConnections: 4, MaxConnectionsPerIP: 2}
	limits, err := cfg.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if limits.ReadHeaderTimeout != cfg.ReadHeaderTimeout || limits.MaxConnections != cfg.MaxConnections || limits.MaxConnectionsPerIP != cfg.MaxConnectionsPerIP {
		t.Fatalf("limits did not preserve overrides: %+v", limits)
	}
	if limits.ReadTimeout == 0 || limits.WriteTimeout == 0 || limits.IdleTimeout == 0 || limits.MaxHeaderBytes == 0 {
		t.Fatalf("missing defaults: %+v", limits)
	}
}

func TestSignerTLSHandshakeDeadline(t *testing.T) {
	limits := shortTestLimits()
	addr, _ := startTestSigner(t, limits)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// No TLS bytes, so authentication is never reached.
	expectClosedWithin(t, conn, 2*time.Second)
}

func TestSignerReadDeadlines(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire string
	}{
		{"partial headers", "POST /v1/sign HTTP/1.1\r\nHost: localhost\r\nX-Stalled: "},
		{"partial body", "POST /v1/sign HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, _ := startTestSigner(t, shortTestLimits())
			conn, err := tls.Dial("tcp", addr, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}) // test-only self-signed certificate
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := io.WriteString(conn, tc.wire); err != nil {
				t.Fatal(err)
			}
			expectClosedWithin(t, conn, 2*time.Second)
		})
	}
}

func TestSignerOversizedHeaderRejected(t *testing.T) {
	limits := shortTestLimits()
	limits.MaxHeaderBytes = 1024
	addr, _ := startTestSigner(t, limits)
	conn, err := tls.Dial("tcp", addr, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}) // test-only self-signed certificate
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	wire := "GET /v1/sign HTTP/1.1\r\nHost: localhost\r\nX-Long: " + strings.Repeat("a", 8192) + "\r\n\r\n"
	if _, err := io.WriteString(conn, wire); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status = %d, want 431", resp.StatusCode)
	}
}

func TestSignerIdleTimeout(t *testing.T) {
	addr, _ := startTestSigner(t, shortTestLimits())
	conn, err := tls.Dial("tcp", addr, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}) // test-only self-signed certificate
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /v1/sign HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
	expectClosedWithin(t, conn, 2*time.Second)
}

func TestSignerConnectionLimits(t *testing.T) {
	for _, tc := range []struct {
		name             string
		maxConnections   int
		maxConnectionsIP int
	}{
		{"global", 1, 2},
		{"per IP", 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limits := shortTestLimits()
			limits.ReadHeaderTimeout = 2 * time.Second
			limits.ReadTimeout = 2 * time.Second
			limits.WriteTimeout = 2 * time.Second
			limits.MaxConnections = tc.maxConnections
			limits.MaxConnectionsPerIP = tc.maxConnectionsIP
			addr, listener := startTestSigner(t, limits)

			first, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			waitActiveConnections(t, listener, 1)

			second, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			expectClosedWithin(t, second, 1*time.Second)
			waitActiveConnections(t, listener, 1)

			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			waitActiveConnections(t, listener, 0)

			third, err := tls.Dial("tcp", addr, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}) // test-only self-signed certificate
			if err != nil {
				t.Fatalf("connection slot was not released: %v", err)
			}
			third.Close()
		})
	}
}

func shortTestLimits() Limits {
	return Limits{
		ReadHeaderTimeout:   100 * time.Millisecond,
		ReadTimeout:         200 * time.Millisecond,
		WriteTimeout:        300 * time.Millisecond,
		IdleTimeout:         100 * time.Millisecond,
		MaxHeaderBytes:      16 << 10,
		MaxConnections:      4,
		MaxConnectionsPerIP: 4,
	}
}

func startTestSigner(t *testing.T, limits Limits) (string, *limitedListener) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	tlsConf := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	limited := newLimitedListener(listener, limits.MaxConnections, limits.MaxConnectionsPerIP)
	srv := newHTTPServer(&signer.Service{}, limits)
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(tls.NewListener(limited, tlsConf))
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve() = %v, want http.ErrServerClosed", err)
		}
	})
	return listener.Addr().String(), limited
}

func waitActiveConnections(t *testing.T, listener *limitedListener, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		listener.mu.Lock()
		active := listener.active
		listener.mu.Unlock()
		if active == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("active connections = %d, want %d", active, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func expectClosedWithin(t *testing.T, conn net.Conn, limit time.Duration) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(limit)); err != nil {
		t.Fatal(err)
	}
	_, err := io.Copy(io.Discard, conn)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("connection remained open beyond %s: %v", limit, err)
	}
}
