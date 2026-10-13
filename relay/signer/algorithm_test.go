package signer_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

type countingSigner struct {
	crypto.Signer
	calls int
}

func (s *countingSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	return s.Signer.Sign(random, digest, opts)
}

func TestSignTranscript_KeyAlgorithmCompatibility(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name      string
		key       crypto.Signer
		algorithm string
		allowed   bool
	}{
		{"RSA/PSS", rsaKey, signrpc.AlgorithmRSAPSSSHA256, true},
		{"RSA/ECDSA", rsaKey, signrpc.AlgorithmECDSASHA256, false},
		{"RSA/Ed25519", rsaKey, signrpc.AlgorithmEd25519, false},
		{"P256/ECDSA", p256Key, signrpc.AlgorithmECDSASHA256, true},
		{"P256/PSS", p256Key, signrpc.AlgorithmRSAPSSSHA256, false},
		{"P256/Ed25519", p256Key, signrpc.AlgorithmEd25519, false},
		{"P384/ECDSA", p384Key, signrpc.AlgorithmECDSASHA256, false},
		{"P384/PSS", p384Key, signrpc.AlgorithmRSAPSSSHA256, false},
		{"P384/Ed25519", p384Key, signrpc.AlgorithmEd25519, false},
		{"Ed25519/ECDSA", ed25519Key, signrpc.AlgorithmECDSASHA256, false},
		{"Ed25519/PSS", ed25519Key, signrpc.AlgorithmRSAPSSSHA256, false},
		{"Ed25519/Ed25519", ed25519Key, signrpc.AlgorithmEd25519, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed := &countingSigner{Signer: tc.key}
			store := signer.NewStaticKeyStore()
			if err := store.Put("test-key", observed); err != nil {
				t.Fatal(err)
			}
			svc := &signer.Service{Store: store}
			req := &signrpc.TranscriptSignRequest{
				KeyID:               "test-key",
				Algorithm:           tc.algorithm,
				ClientHello:         []byte("client-hello"),
				ServerHello:         []byte("server-hello"),
				EncryptedExtensions: []byte("extensions"),
				Certificate:         []byte("certificate"),
				TimestampUnix:       time.Now().Unix(),
				Nonce:               "nonce",
			}
			resp, err := svc.SignTranscript(context.Background(), req)
			if !tc.allowed {
				if !errors.Is(err, signer.ErrInvalidArgument) {
					t.Fatalf("expected ErrInvalidArgument, got response=%v, err=%v", resp, err)
				}
				if observed.calls != 0 {
					t.Fatalf("incompatible algorithm reached crypto.Signer.Sign %d times", observed.calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected a signature: %v", err)
			}
			if observed.calls != 1 {
				t.Fatalf("expected one signing operation, got %d", observed.calls)
			}
			if resp.KeyID != req.KeyID || resp.Algorithm != req.Algorithm {
				t.Fatalf("incorrect response metadata: %+v", resp)
			}

			h := sha256.New()
			h.Write(req.ClientHello)
			h.Write(req.ServerHello)
			h.Write(req.EncryptedExtensions)
			h.Write(req.Certificate)
			content := signer.FormatCertificateVerifyContent(h.Sum(nil))
			digest := sha256.Sum256(content)
			switch key := tc.key.(type) {
			case *rsa.PrivateKey:
				if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], resp.Signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
					t.Fatalf("RSA-PSS verification failed: %v", err)
				}
			case *ecdsa.PrivateKey:
				if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], resp.Signature) {
					t.Fatal("ECDSA signature verification failed")
				}
			case ed25519.PrivateKey:
				if !ed25519.Verify(key.Public().(ed25519.PublicKey), content, resp.Signature) {
					t.Fatal("Ed25519 signature verification failed")
				}
			default:
				t.Fatalf("unexpected key type: %T", key)
			}
		})
	}
}
