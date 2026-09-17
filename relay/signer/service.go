package signer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"time"

	"github.com/gosuda/keyless_tls/relay/signrpc"
)

var (
	ErrInvalidArgument  = errors.New("invalid argument")
	ErrPermissionDenied = errors.New("permission denied")
	ErrInternal         = errors.New("internal")
)

type TranscriptValidator interface {
	ValidateTranscript(ctx context.Context, req *signrpc.TranscriptSignRequest) error
}

type TranscriptValidatorFunc func(ctx context.Context, req *signrpc.TranscriptSignRequest) error

func (f TranscriptValidatorFunc) ValidateTranscript(ctx context.Context, req *signrpc.TranscriptSignRequest) error {
	return f(ctx, req)
}

type Service struct {
	Store                        KeyStore
	AllowedSkew                  time.Duration
	TranscriptValidator          TranscriptValidator
	AllowUnboundTranscriptSigning bool
}

func (s *Service) Sign(ctx context.Context, req *signrpc.SignRequest) (*signrpc.SignResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: request is nil", ErrInvalidArgument)
	}
	if req.KeyID == "" || len(req.Digest) == 0 || req.Algorithm == "" || req.Nonce == "" {
		return nil, fmt.Errorf("%w: missing required field", ErrInvalidArgument)
	}
	if s.Store == nil {
		return nil, fmt.Errorf("%w: signer store is not configured", ErrInternal)
	}

	skew := s.AllowedSkew
	if skew <= 0 {
		skew = 30 * time.Second
	}
	now := time.Now().Unix()
	if req.TimestampUnix < now-int64(skew.Seconds()) || req.TimestampUnix > now+int64(skew.Seconds()) {
		return nil, fmt.Errorf("%w: request timestamp outside allowed skew", ErrInvalidArgument)
	}

	signer, err := s.Store.Signer(ctx, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrPermissionDenied, err.Error())
	}

	sig, err := signByAlgorithm(signer, req.Digest, req.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidArgument, err.Error())
	}

	return &signrpc.SignResponse{KeyID: req.KeyID, Algorithm: req.Algorithm, Signature: sig}, nil
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
	} else if !s.AllowUnboundTranscriptSigning {
		return nil, fmt.Errorf("%w: transcript validator is required (or set AllowUnboundTranscriptSigning)", ErrPermissionDenied)
	}

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
	case signrpc.AlgorithmECDSASHA256, signrpc.AlgorithmRSAPSSSHA256, signrpc.AlgorithmRSAPKCS1v15SHA256:
		h := sha256.Sum256(content)
		return h[:], nil
	case signrpc.AlgorithmECDSASHA384, signrpc.AlgorithmRSAPSSSHA384, signrpc.AlgorithmRSAPKCS1v15SHA384:
		h := sha512.Sum384(content)
		return h[:], nil
	case signrpc.AlgorithmECDSASHA512, signrpc.AlgorithmRSAPSSSHA512, signrpc.AlgorithmRSAPKCS1v15SHA512:
		h := sha512.Sum512(content)
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

	switch algorithm {
	case signrpc.AlgorithmECDSASHA256:
		return signer.Sign(rand.Reader, digest, crypto.SHA256)
	case signrpc.AlgorithmECDSASHA384:
		return signer.Sign(rand.Reader, digest, crypto.SHA384)
	case signrpc.AlgorithmECDSASHA512:
		return signer.Sign(rand.Reader, digest, crypto.SHA512)
	case signrpc.AlgorithmRSAPKCS1v15SHA256:
		return signer.Sign(rand.Reader, digest, crypto.SHA256)
	case signrpc.AlgorithmRSAPKCS1v15SHA384:
		return signer.Sign(rand.Reader, digest, crypto.SHA384)
	case signrpc.AlgorithmRSAPKCS1v15SHA512:
		return signer.Sign(rand.Reader, digest, crypto.SHA512)
	case signrpc.AlgorithmRSAPSSSHA256:
		return signer.Sign(rand.Reader, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	case signrpc.AlgorithmRSAPSSSHA384:
		return signer.Sign(rand.Reader, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA384})
	case signrpc.AlgorithmRSAPSSSHA512:
		return signer.Sign(rand.Reader, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512})
	case signrpc.AlgorithmEd25519:
		return signer.Sign(rand.Reader, digest, crypto.Hash(0))
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}
