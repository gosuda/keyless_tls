package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/internal/testutil"
)

func TestSignerLimits(t *testing.T) {
	defaults, err := (Limits{}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if defaults.MaxConnections <= 0 || defaults.MaxConnectionsPerIP <= 0 ||
		defaults.MaxConnectionsPerIP > defaults.MaxConnections ||
		defaults.ReadHeaderTimeout <= 0 || defaults.ReadTimeout <= 0 ||
		defaults.WriteTimeout <= 0 || defaults.IdleTimeout <= 0 ||
		defaults.MaxHeaderBytes <= 0 {
		t.Fatalf("unsafe default limits: %+v", defaults)
	}

	for _, tc := range []struct {
		name   string
		limits Limits
	}{
		{"negative connection cap", Limits{MaxConnections: -1}},
		{"negative source cap", Limits{MaxConnectionsPerIP: -1}},
		{"negative handshake limit", Limits{ReadHeaderTimeout: -time.Second}},
		{"negative read limit", Limits{ReadTimeout: -time.Second}},
		{"negative write limit", Limits{WriteTimeout: -time.Second}},
		{"negative idle limit", Limits{IdleTimeout: -time.Second}},
		{"negative header cap", Limits{MaxHeaderBytes: -1}},
		{"source cap greater than total", Limits{MaxConnections: 1, MaxConnectionsPerIP: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.limits.withDefaults(); err == nil {
				t.Fatal("expected invalid limits to be rejected")
			}
		})
	}
}

func TestSignerTLSHandshakeDeadline(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("signer.test", false)
	if err != nil {
		t.Fatal(err)
	}
	clientCA, _, err := testutil.GenerateCert("client.test", true)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := serverTLSConfig(certPEM, keyPEM, clientCA)
	if err != nil {
		t.Fatal(err)
	}
	addr := startSecurityTestServer(t, conf, Limits{ReadHeaderTimeout: 100 * time.Millisecond})

	// Do not send a ClientHello. The connection must close before mTLS.
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	expectPeerClose(t, conn)
}

func TestSignerSlowHTTPReads(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("signer.test", false)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := serverTLSConfig(certPEM, keyPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := startSecurityTestServer(t, conf, Limits{
		ReadHeaderTimeout: 100 * time.Millisecond,
		ReadTimeout:       250 * time.Millisecond,
		WriteTimeout:      time.Second,
	})

	for _, tc := range []struct {
		name    string
		request string
	}{
		{"incomplete headers", "POST /v1/sign HTTP/1.1\r\nHost: "},
		{"incomplete body", "POST /v1/sign HTTP/1.1\r\nHost: signer.test\r\nContent-Length: 500\r\nConnection: close\r\n\r\n{"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Ephemeral, self-signed certificate used only by this test.
			conn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: time.Second}, "tcp", addr,
				&tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true},
			)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := io.WriteString(conn, tc.request); err != nil {
				t.Fatal(err)
			}
			expectPeerClose(t, conn)
		})
	}
}

func TestSignerIdleDeadline(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCert("signer.test", false)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := serverTLSConfig(certPEM, keyPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := startSecurityTestServer(t, conf, Limits{IdleTimeout: 100 * time.Millisecond})
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: time.Second}, "tcp", addr,
		&tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: signer.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	expectPeerClose(t, conn)
}

func TestSignerConnectionAdmissionLimits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		limits  Limits
		allowed int
	}{
		{"per source", Limits{MaxConnections: 2, MaxConnectionsPerIP: 1}, 1},
		{"global", Limits{MaxConnections: 2, MaxConnectionsPerIP: 2}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			limits, err := tc.limits.withDefaults()
			if err != nil {
				t.Fatal(err)
			}
			listener := newConnectionLimitListener(raw, limits)
			accepted := make(chan net.Conn, tc.allowed+1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					accepted <- conn
				}
			}()
			t.Cleanup(func() {
				_ = listener.Close()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Error("listener did not stop")
				}
			})

			servers := make([]net.Conn, 0, tc.allowed)
			for range tc.allowed {
				client, err := net.DialTimeout("tcp", raw.Addr().String(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				select {
				case server := <-accepted:
					servers = append(servers, server)
					defer server.Close()
				case <-time.After(time.Second):
					t.Fatal("connection was not admitted")
				}
			}

			excess, err := net.DialTimeout("tcp", raw.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer excess.Close()
			expectPeerClose(t, excess)

			if err := servers[0].Close(); err != nil {
				t.Fatal(err)
			}
			_ = servers[0].Close() // Release capacity exactly once.

			replacement, err := net.DialTimeout("tcp", raw.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer replacement.Close()
			select {
			case server := <-accepted:
				defer server.Close()
			case <-time.After(time.Second):
				t.Fatal("connection capacity was not released")
			}
		})
	}
}

func startSecurityTestServer(t *testing.T, conf *tls.Config, limits Limits) string {
	t.Helper()
	limits, err := limits.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, lis, conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				http.Error(w, "body read failed", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}), limits)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("signer server exited: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("signer server did not shut down")
		}
	})
	return lis.Addr().String()
}

func expectPeerClose(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatalf("expected peer to close before deadline, got %v", err)
	}
}
