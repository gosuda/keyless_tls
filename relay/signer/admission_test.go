package signer_test

import (
	"context"
	"crypto"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

type gatedSigner struct {
	started chan struct{}
	release <-chan struct{}
}

func (s *gatedSigner) Public() crypto.PublicKey { return nil }

func (s *gatedSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	s.started <- struct{}{}
	<-s.release
	return []byte("signature"), nil
}

type allKeysStore struct{ key crypto.Signer }

func (s allKeysStore) Signer(context.Context, string) (crypto.Signer, error) {
	return s.key, nil
}

func signRequest(keyID string) *signrpc.TranscriptSignRequest {
	return &signrpc.TranscriptSignRequest{
		KeyID:               keyID,
		Algorithm:           signrpc.AlgorithmECDSASHA256,
		Nonce:               "nonce",
		ClientHello:         []byte("ch"),
		ServerHello:         []byte("sh"),
		EncryptedExtensions: []byte("ee"),
		Certificate:         []byte("cert"),
		TimestampUnix:       time.Now().Unix(),
	}
}

func TestServiceSigningAdmission(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)

	svc := &signer.Service{
		Store:                    allKeysStore{key: &gatedSigner{started: started, release: release}},
		MaxConcurrentSigns:       2,
		MaxConcurrentSignsPerKey: 1,
	}
	results := make(chan error, 2)
	for _, id := range []string{"a", "b"} {
		go func(keyID string) {
			_, err := svc.SignTranscript(context.Background(), signRequest(keyID))
			results <- err
		}(id)
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("signer did not start")
		}
	}

	for _, id := range []string{"a", "c"} {
		if _, err := svc.SignTranscript(context.Background(), signRequest(id)); !errors.Is(err, signer.ErrOverloaded) {
			t.Fatalf("key %s: expected ErrOverloaded, got %v", id, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.SignTranscript(ctx, signRequest("d")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation before signing, got %v", err)
	}
	if got := svc.RejectedSignatures(); got != 2 {
		t.Fatalf("rejected signatures = %d, want 2", got)
	}

	unblock()
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("admitted request failed: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("admitted request did not finish")
		}
	}
	if _, err := svc.SignTranscript(context.Background(), signRequest("a")); err != nil {
		t.Fatalf("capacity was not released: %v", err)
	}
}
