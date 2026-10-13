package signer_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

type staticStore struct {
	keyID  string
	signer crypto.Signer
}

func (s *staticStore) Signer(_ context.Context, keyID string) (crypto.Signer, error) {
	if keyID == s.keyID {
		return s.signer, nil
	}
	return nil, errors.New("key not found")
}

func TestSignTranscript_Success(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	store := &staticStore{keyID: "test-key", signer: priv}
	validated := false
	validator := signer.TranscriptValidatorFunc(func(ctx context.Context, req *signrpc.TranscriptSignRequest) error {
		if string(req.Binding) != "expected-binding" {
			return errors.New("invalid binding")
		}
		validated = true
		return nil
	})

	svc := &signer.Service{
		Store:               store,
		TranscriptValidator: validator,
	}

	req := &signrpc.TranscriptSignRequest{
		KeyID:               "test-key",
		Algorithm:           signrpc.AlgorithmECDSASHA256,
		Binding:             []byte("expected-binding"),
		ClientHello:         []byte("mock-client-hello"),
		ServerHello:         []byte("mock-server-hello"),
		EncryptedExtensions: []byte("mock-ee"),
		Certificate:         []byte("mock-cert"),
		TimestampUnix:       time.Now().Unix(),
		Nonce:               "test-nonce",
	}

	resp, err := svc.SignTranscript(context.Background(), req)
	if err != nil {
		t.Fatalf("SignTranscript failed: %v", err)
	}

	if !validated {
		t.Fatal("expected validator to be called")
	}
	if len(resp.Signature) == 0 {
		t.Fatal("empty signature in response")
	}

	// Verify the signature against the expected RFC 8446 CertificateVerify content
	h := sha256.New()
	h.Write(req.ClientHello)
	h.Write(req.ServerHello)
	h.Write(req.EncryptedExtensions)
	h.Write(req.Certificate)
	transcriptHash := h.Sum(nil)

	content := signer.FormatCertificateVerifyContent(transcriptHash)
	contentHash := sha256.Sum256(content)

	if !ecdsa.VerifyASN1(&priv.PublicKey, contentHash[:], resp.Signature) {
		t.Fatal("signature verification failed against RFC 8446 pre-image")
	}
}

func TestSignTranscript_ValidatorRejects(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	store := &staticStore{keyID: "test-key", signer: priv}
	validator := signer.TranscriptValidatorFunc(func(ctx context.Context, req *signrpc.TranscriptSignRequest) error {
		return errors.New("binding rejected")
	})

	svc := &signer.Service{
		Store:               store,
		TranscriptValidator: validator,
	}

	req := &signrpc.TranscriptSignRequest{
		KeyID:               "test-key",
		Algorithm:           signrpc.AlgorithmECDSASHA256,
		Binding:             []byte("unauthorized-binding"),
		ClientHello:         []byte("mock-client-hello"),
		ServerHello:         []byte("mock-server-hello"),
		EncryptedExtensions: []byte("mock-ee"),
		Certificate:         []byte("mock-cert"),
		TimestampUnix:       time.Now().Unix(),
		Nonce:               "test-nonce",
	}

	_, err = svc.SignTranscript(context.Background(), req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, signer.ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestSignTranscript_ValidationErrors(t *testing.T) {
	svc := &signer.Service{Store: &staticStore{}}

	// nil request
	if _, err := svc.SignTranscript(context.Background(), nil); !errors.Is(err, signer.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for nil req, got %v", err)
	}

	// missing fields
	req := &signrpc.TranscriptSignRequest{
		KeyID:     "key",
		Algorithm: signrpc.AlgorithmECDSASHA256,
		Nonce:     "nonce",
	}
	if _, err := svc.SignTranscript(context.Background(), req); !errors.Is(err, signer.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for missing transcript, got %v", err)
	}

	// expired timestamp
	req = &signrpc.TranscriptSignRequest{
		KeyID:               "key",
		Algorithm:           signrpc.AlgorithmECDSASHA256,
		Nonce:               "nonce",
		ClientHello:         []byte("ch"),
		ServerHello:         []byte("sh"),
		EncryptedExtensions: []byte("ee"),
		Certificate:         []byte("cert"),
		TimestampUnix:       time.Now().Unix() - 1000,
	}
	if _, err := svc.SignTranscript(context.Background(), req); !errors.Is(err, signer.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for skewed timestamp, got %v", err)
	}
}

func TestSignTranscript_SignsWithoutValidator(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	store := &staticStore{keyID: "test-key", signer: priv}

	// A nil validator is the library primitive: structurally valid requests
	// are signed. Enforcing binding semantics is the deployer's policy, so
	// policy-carrying deployments configure a TranscriptValidator.
	svc := &signer.Service{Store: store}
	req := &signrpc.TranscriptSignRequest{
		KeyID:               "test-key",
		Algorithm:           signrpc.AlgorithmECDSASHA256,
		Binding:             []byte("any-binding"),
		ClientHello:         []byte("ch"),
		ServerHello:         []byte("sh"),
		EncryptedExtensions: []byte("ee"),
		Certificate:         []byte("cert"),
		TimestampUnix:       time.Now().Unix(),
		Nonce:               "nonce",
	}
	resp, err := svc.SignTranscript(context.Background(), req)
	if err != nil {
		t.Fatalf("expected success without validator, got %v", err)
	}
	if len(resp.Signature) == 0 {
		t.Fatal("empty signature")
	}
}

type blockingCryptoSigner struct {
	entered chan struct{}
	release <-chan struct{}
	active atomic.Int32
	peak atomic.Int32
}

func (s *blockingCryptoSigner) Public() crypto.PublicKey { return nil }

func (s *blockingCryptoSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	current := s.active.Add(1)
	defer s.active.Add(-1)
	for {
		old := s.peak.Load()
		if current <= old || s.peak.CompareAndSwap(old, current) {
			break
		}
	}
	s.entered <- struct{}{}
	<-s.release
	return []byte{1}, nil
}

type keyedStore map[string]crypto.Signer

func (s keyedStore) Signer(_ context.Context, key string) (crypto.Signer, error) {
	signer, ok := s[key]
	if !ok {
		return nil, errors.New("key not found")
	}
	return signer, nil
}

func signRequest(key string) *signrpc.TranscriptSignRequest {
	return &signrpc.TranscriptSignRequest{
		KeyID: key, Algorithm: signrpc.AlgorithmECDSASHA256, Nonce: "unique-nonce",
		ClientHello: []byte("ch"), ServerHello: []byte("sh"),
		EncryptedExtensions: []byte("ee"), Certificate: []byte("cert"),
		TimestampUnix: time.Now().Unix(),
	}
}

func TestSignTranscript_BoundsConcurrentSignOperations(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	blocker := &blockingCryptoSigner{entered: make(chan struct{}, 2), release: release}
	svc := &signer.Service{
		Store: keyedStore{"a": blocker, "b": blocker, "c": blocker},
		MaxConcurrentSigns: 2,
		MaxConcurrentSignsPerKey: 1,
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, key := range []string{"a", "b"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.SignTranscript(context.Background(), signRequest(key))
			errs <- err
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-blocker.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("sign operation did not start")
		}
	}
	if _, err := svc.SignTranscript(context.Background(), signRequest("a")); !errors.Is(err, signer.ErrOverloaded) {
		t.Fatalf("same key should be rejected while busy, got %v", err)
	}
	if _, err := svc.SignTranscript(context.Background(), signRequest("c")); !errors.Is(err, signer.ErrOverloaded) {
		t.Fatalf("global signing limit should reject new key, got %v", err)
	}
	if got := svc.RejectedSigns(); got != 2 {
		t.Fatalf("overload metric = %d, want 2", got)
	}
	unblock()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("admitted signing failed: %v", err)
		}
	}
	if got := blocker.peak.Load(); got != 2 {
		t.Fatalf("peak concurrent signatures = %d, want 2", got)
	}
	if _, err := svc.SignTranscript(context.Background(), signRequest("c")); err != nil {
		t.Fatalf("released signing slot was not reusable: %v", err)
	}
}

func TestSignTranscript_CancelledBeforeSigning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	svc := &signer.Service{
		Store: keyedStore{"a": &blockingCryptoSigner{
			entered: make(chan struct{}, 1),
			release: closedChannel(),
		}},
		MaxConcurrentSigns: 1,
	}
	if _, err := svc.SignTranscript(ctx, signRequest("a")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request returned %v", err)
	}
	if _, err := svc.SignTranscript(context.Background(), signRequest("a")); err != nil {
		t.Fatalf("canceled request retained a signing slot: %v", err)
	}
}

func closedChannel() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}
