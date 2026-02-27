package signer

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"keyless_tls/relay/signrpc"
)

type Service struct {
	signrpc.UnimplementedSignerServiceServer

	Store       KeyStore
	AllowedSkew time.Duration
}

func (s *Service) Sign(ctx context.Context, req *signrpc.SignRequest) (*signrpc.SignResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is nil")
	}
	if req.KeyID == "" || len(req.Digest) == 0 || req.Algorithm == "" || req.Nonce == "" {
		return nil, status.Error(codes.InvalidArgument, "missing required field")
	}
	if s.Store == nil {
		return nil, status.Error(codes.Internal, "signer store is not configured")
	}

	skew := s.AllowedSkew
	if skew <= 0 {
		skew = 30 * time.Second
	}
	now := time.Now().Unix()
	if req.TimestampUnix < now-int64(skew.Seconds()) || req.TimestampUnix > now+int64(skew.Seconds()) {
		return nil, status.Error(codes.InvalidArgument, "request timestamp outside allowed skew")
	}

	signer, err := s.Store.Signer(ctx, req.KeyID)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}

	sig, err := signByAlgorithm(signer, req.Digest, req.Algorithm)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
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
