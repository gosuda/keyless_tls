package signer_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
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

func TestSignTranscript_FailClosedWithoutValidator(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	store := &staticStore{keyID: "test-key", signer: priv}

	// Without validator and without AllowUnboundTranscriptSigning: MUST FAIL
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
	_, err = svc.SignTranscript(context.Background(), req)
	if !errors.Is(err, signer.ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied when validator is omitted, got %v", err)
	}

	// With AllowUnboundTranscriptSigning: true: SUCCESS
	svc.AllowUnboundTranscriptSigning = true
	resp, err := svc.SignTranscript(context.Background(), req)
	if err != nil {
		t.Fatalf("expected success with AllowUnboundTranscriptSigning, got %v", err)
	}
	if len(resp.Signature) == 0 {
		t.Fatal("empty signature")
	}
}

