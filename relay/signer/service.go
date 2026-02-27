package signer

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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

type Service struct {
	Store       KeyStore
	AllowedSkew time.Duration
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
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}
