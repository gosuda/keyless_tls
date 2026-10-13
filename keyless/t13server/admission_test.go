package t13server

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/internal/testutil"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

type admissionCountingSigner struct{ calls atomic.Uint64 }

func (s *admissionCountingSigner) SignTranscript(context.Context, *signrpc.TranscriptSignRequest) (*signrpc.TranscriptSignResponse, error) {
	s.calls.Add(1)
	return nil, errors.New("unexpected signing request")
}

func newAdmissionServer(t *testing.T, signer *admissionCountingSigner, maxConcurrent, rate, burst int) *Server {
	t.Helper()
	certPEM, _, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	srv, err := NewServer(Config{
		CertPEM:                      certPEM,
		TranscriptSigner:             signer,
		MaxConcurrentHandshakes:      maxConcurrent,
		MaxConcurrentHandshakesPerIP: 1,
		HandshakeRatePerIP:           rate,
		HandshakeBurstPerIP:          burst,
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	return srv
}

func TestHandshakeFloodRejectedBeforeRemoteSigning(t *testing.T) {
	signer := &admissionCountingSigner{}
	srv := newAdmissionServer(t, signer, 1, 100, 100)
	if !srv.handshakes.TryAcquire("pipe") {
		t.Fatal("failed to reserve the sole handshake slot")
	}
	defer srv.handshakes.Release("pipe")

	const attempts = 50
	for range attempts {
		raw, peer := net.Pipe()
		conn := srv.NewConn(raw, nil)
		if err := conn.HandshakeContext(context.Background()); !errors.Is(err, ErrHandshakeOverloaded) {
			t.Errorf("expected handshake overload before ClientHello, got %v", err)
		}
		_ = raw.Close()
		_ = peer.Close()
	}
	if got := signer.calls.Load(); got != 0 {
		t.Fatalf("remote signer called %d times for rejected handshakes", got)
	}
	if got := srv.RejectedHandshakes(); got != attempts {
		t.Fatalf("rejected handshakes = %d, want %d", got, attempts)
	}
}

func TestHandshakePerSourceRateLimit(t *testing.T) {
	signer := &admissionCountingSigner{}
	srv := newAdmissionServer(t, signer, 2, 1, 1)
	if !srv.sourceRates.Allow("pipe", time.Now()) {
		t.Fatal("failed to use initial source token")
	}
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	if err := srv.NewConn(raw, nil).HandshakeContext(context.Background()); !errors.Is(err, ErrHandshakeOverloaded) {
		t.Fatalf("expected rate limit before ClientHello, got %v", err)
	}
	if got := signer.calls.Load(); got != 0 {
		t.Fatalf("signer called %d times on rejected handshake", got)
	}
	if got := srv.RejectedHandshakes(); got != 1 {
		t.Fatalf("rejections = %d, want 1", got)
	}
}
