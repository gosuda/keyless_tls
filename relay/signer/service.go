package signer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosuda/keyless_tls/internal/admission"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

var (
	ErrInvalidArgument  = errors.New("invalid argument")
	ErrPermissionDenied = errors.New("permission denied")
	ErrInternal         = errors.New("internal")
	ErrOverloaded       = errors.New("signing capacity exhausted")
)

const (
	defaultMaxConcurrentSigns       = 32
	defaultMaxConcurrentSignsPerKey = 8
)

type TranscriptValidator interface {
	ValidateTranscript(ctx context.Context, req *signrpc.TranscriptSignRequest) error
}

type TranscriptValidatorFunc func(ctx context.Context, req *signrpc.TranscriptSignRequest) error

func (f TranscriptValidatorFunc) ValidateTranscript(ctx context.Context, req *signrpc.TranscriptSignRequest) error {
	return f(ctx, req)
}

// Service signs TLS 1.3 CertificateVerify transcripts for the /v1/sign
// endpoint. The library owns the mechanism: the request must carry the
// handshake transcript, the timestamp must be fresh, and the signature must
// answer exactly that transcript. Whether a request needs additional
// authorization is deployment policy, so the optional TranscriptValidator is
// the only policy hook: when it is nil, every structurally valid request is
// signed, and consumers that enforce binding semantics (leases, streams,
// hostnames) must configure one.
type Service struct {
	Store               KeyStore
	AllowedSkew         time.Duration
	TranscriptValidator TranscriptValidator

	// Zero uses the safe defaults (32 globally, eight per key). Set before
	// the first request; do not modify configuration during concurrent use.
	MaxConcurrentSigns       int
	MaxConcurrentSignsPerKey int

	admissionOnce sync.Once
	admission     *admission.Limiter
	rejectedSigns atomic.Uint64
}

// RejectedSigns reports overload decisions made by this service.
func (s *Service) RejectedSigns() uint64 {
	return s.rejectedSigns.Load()
}

func (s *Service) signingAdmission() *admission.Limiter {
	s.admissionOnce.Do(func() {
		total := s.MaxConcurrentSigns
		if total == 0 {
			total = defaultMaxConcurrentSigns
		}
		perKey := s.MaxConcurrentSignsPerKey
		if perKey == 0 {
			perKey = defaultMaxConcurrentSignsPerKey
		}
		s.admission = admission.New(admission.Limits{
			MaxConcurrent:  total,
			MaxPerIdentity: perKey,
			MaxIdentities:  total,
		})
	})
	return s.admission
}

func (s *Service) SignTranscript(ctx context.Context, req *signrpc.TranscriptSignRequest) (*signrpc.TranscriptSignResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: request is nil", ErrInvalidArgument)
	}
	if req.KeyID == "" || req.Algorithm == "" || req.Nonce == "" {
		return nil, fmt.Errorf("%w: missing required metadata field", ErrInvalidArgument)
	}
	if len(req.ClientHello) == 0 || len(req.ServerHello) == 0 || len(req.EncryptedExtensions) == 0 || len(req.Certificate) == 0 {
		return nil, fmt.Errorf("%w: missing required handshake transcript field", ErrInvalidArgument)
	}
	if s.Store == nil {
		return nil, fmt.Errorf("%w: signer store is not configured", ErrInternal)
	}
	if s.MaxConcurrentSigns < 0 || s.MaxConcurrentSignsPerKey < 0 {
		return nil, fmt.Errorf("%w: signing concurrency limits must not be negative", ErrInternal)
	}

	skew := s.AllowedSkew
	if skew <= 0 {
		skew = 30 * time.Second
	}
	now := time.Now().Unix()
	if req.TimestampUnix < now-int64(skew.Seconds()) || req.TimestampUnix > now+int64(skew.Seconds()) {
		return nil, fmt.Errorf("%w: request timestamp outside allowed skew", ErrInvalidArgument)
	}

	if s.TranscriptValidator != nil {
		if err := s.TranscriptValidator.ValidateTranscript(ctx, req); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrPermissionDenied, err.Error())
		}
	}

	// Fail fast rather than starting an unbounded number of crypto.Signer
	// calls. The permit covers key lookup too, since HSM-backed stores may
	// allocate scarce sessions during lookup.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	limiter := s.signingAdmission()
	if !limiter.TryAcquire(req.KeyID) {
		s.rejectedSigns.Add(1)
		return nil, ErrOverloaded
	}
	defer limiter.Release(req.KeyID)

	signer, err := s.Store.Signer(ctx, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrPermissionDenied, err.Error())
	}

	transcriptHash := computeTranscriptHash(req)

	content := FormatCertificateVerifyContent(transcriptHash)
	digest, err := hashContentForAlgorithm(content, req.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidArgument, err.Error())
	}

	sig, err := signByAlgorithm(signer, digest, req.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidArgument, err.Error())
	}

	return &signrpc.TranscriptSignResponse{
		KeyID:     req.KeyID,
		Algorithm: req.Algorithm,
		Signature: sig,
	}, nil
}

func FormatCertificateVerifyContent(transcriptHash []byte) []byte {
	prefix := bytes.Repeat([]byte{0x20}, 64)
	contextStr := []byte("TLS 1.3, server CertificateVerify\x00")
	out := make([]byte, 0, len(prefix)+len(contextStr)+len(transcriptHash))
	out = append(out, prefix...)
	out = append(out, contextStr...)
	out = append(out, transcriptHash...)
	return out
}

// computeTranscriptHash computes the TLS 1.3 transcript hash.
// In RFC 8446 Section 7.1, the transcript hash is determined by the cipher suite
// (here TLS_AES_128_GCM_SHA256, so SHA-256), not by the CertificateVerify signature algorithm.
func computeTranscriptHash(req *signrpc.TranscriptSignRequest) []byte {
	h := sha256.New()
	h.Write(req.ClientHello)
	h.Write(req.ServerHello)
	h.Write(req.EncryptedExtensions)
	h.Write(req.Certificate)
	return h.Sum(nil)
}

func hashContentForAlgorithm(content []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case signrpc.AlgorithmECDSASHA256, signrpc.AlgorithmRSAPSSSHA256:
		h := sha256.Sum256(content)
		return h[:], nil
	case signrpc.AlgorithmEd25519:
		return content, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm for content hashing: %s", algorithm)
	}
}

func signByAlgorithm(signer crypto.Signer, digest []byte, algorithm string) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("signer is nil")
	}

	// The key, not the caller, determines which TLS signature scheme is allowed.
	var compatible bool
	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey:
		compatible = pub != nil && pub.Curve == elliptic.P256() && algorithm == signrpc.AlgorithmECDSASHA256
	case *rsa.PublicKey:
		compatible = pub != nil && algorithm == signrpc.AlgorithmRSAPSSSHA256
	case ed25519.PublicKey:
		compatible = len(pub) == ed25519.PublicKeySize && algorithm == signrpc.AlgorithmEd25519
	}
	if !compatible {
		return nil, fmt.Errorf("algorithm %q is incompatible with signer public key", algorithm)
	}

	switch algorithm {
	case signrpc.AlgorithmECDSASHA256:
		return signer.Sign(rand.Reader, digest, crypto.SHA256)
	case signrpc.AlgorithmRSAPSSSHA256:
		return signer.Sign(rand.Reader, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	case signrpc.AlgorithmEd25519:
		return signer.Sign(rand.Reader, digest, crypto.Hash(0))
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}
