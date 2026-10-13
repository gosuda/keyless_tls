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

type recordingSigner struct {
	crypto.Signer
	calls int
}

func (s *recordingSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	return s.Signer.Sign(random, digest, opts)
}

func TestSignTranscript_KeyAlgorithmCompatibility(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}

	keys := []struct {
		name             string
		key              crypto.Signer
		allowedAlgorithm string
	}{
		{"RSA", rsaKey, signrpc.AlgorithmRSAPSSSHA256},
		{"P-256", ecdsaKey, signrpc.AlgorithmECDSASHA256},
		{"P-384", p384Key, ""},
		{"Ed25519", ed25519Key, signrpc.AlgorithmEd25519},
	}
	algorithms := []string{
		signrpc.AlgorithmECDSASHA256,
		signrpc.AlgorithmRSAPSSSHA256,
		signrpc.AlgorithmEd25519,
		"UNSUPPORTED",
	}

	for _, tc := range keys {
		for _, algorithm := range algorithms {
			t.Run(tc.name+"/"+algorithm, func(t *testing.T) {
				observed := &recordingSigner{Signer: tc.key}
				store := signer.NewStaticKeyStore()
				if err := store.Put("test-key", observed); err != nil {
					t.Fatalf("store signing key: %v", err)
				}
				svc := &signer.Service{Store: store}
				req := &signrpc.TranscriptSignRequest{
					KeyID:               "test-key",
					Algorithm:           algorithm,
					ClientHello:         []byte("client-hello"),
					ServerHello:         []byte("server-hello"),
					EncryptedExtensions: []byte("encrypted-extensions"),
					Certificate:         []byte("certificate"),
					TimestampUnix:       time.Now().Unix(),
					Nonce:               "nonce",
				}

				resp, err := svc.SignTranscript(context.Background(), req)
				if algorithm != tc.allowedAlgorithm {
					if !errors.Is(err, signer.ErrInvalidArgument) {
						t.Fatalf("expected ErrInvalidArgument, got %v", err)
					}
					if resp != nil {
						t.Fatal("unexpected signature response")
					}
					if observed.calls != 0 {
						t.Fatalf("incompatible request invoked Sign %d times", observed.calls)
					}
					return
				}
				if err != nil {
					t.Fatalf("sign matching request: %v", err)
				}
				if observed.calls != 1 {
					t.Fatalf("expected one Sign invocation, got %d", observed.calls)
				}
				if resp.Algorithm != algorithm {
					t.Fatalf("response algorithm = %q, want %q", resp.Algorithm, algorithm)
				}

				h := sha256.New()
				h.Write(req.ClientHello)
				h.Write(req.ServerHello)
				h.Write(req.EncryptedExtensions)
				h.Write(req.Certificate)
				content := signer.FormatCertificateVerifyContent(h.Sum(nil))
				digest := sha256.Sum256(content)
				switch pub := tc.key.Public().(type) {
				case *rsa.PublicKey:
					if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], resp.Signature, &rsa.PSSOptions{
						SaltLength: rsa.PSSSaltLengthEqualsHash,
						Hash:       crypto.SHA256,
					}); err != nil {
						t.Fatalf("verify RSA-PSS signature: %v", err)
					}
				case *ecdsa.PublicKey:
					if !ecdsa.VerifyASN1(pub, digest[:], resp.Signature) {
						t.Fatal("invalid ECDSA signature")
					}
				case ed25519.PublicKey:
					if !ed25519.Verify(pub, content, resp.Signature) {
						t.Fatal("invalid Ed25519 signature")
					}
				default:
					t.Fatalf("unexpected signer public key type %T", pub)
				}
			})
		}
	}
}
