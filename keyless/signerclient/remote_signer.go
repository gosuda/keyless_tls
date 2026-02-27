package signerclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"keyless_tls/relay/signrpc"
)

type RemoteSigner struct {
	keyID     string
	publicKey crypto.PublicKey
	client    signrpc.SignerServiceClient
	conn      *grpc.ClientConn
	timeout   time.Duration
}

func NewRemoteSigner(cfg RemoteSignerConfig, certPEM []byte) (*RemoteSigner, error) {
	cfg.applyDefaults()
	if cfg.Endpoint == "" {
		return nil, errors.New("endpoint is required")
	}
	if cfg.KeyID == "" {
		return nil, errors.New("key id is required")
	}
	if len(certPEM) == 0 {
		return nil, errors.New("certificate PEM is required")
	}

	pub, err := parsePublicKeyFromCert(certPEM)
	if err != nil {
		return nil, err
	}

	tlsConf, err := signerTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(
		cfg.Endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(signrpc.JSONCodec{})),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 5 * time.Second}),
	)
	if err != nil {
		return nil, fmt.Errorf("dial signer service: %w", err)
	}

	return &RemoteSigner{
		keyID:     cfg.KeyID,
		publicKey: pub,
		client:    signrpc.NewSignerServiceClient(conn),
		conn:      conn,
		timeout:   cfg.Timeout,
	}, nil
}

func signerTLSConfig(cfg RemoteSignerConfig) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cfg.RootCAPEM) {
		return nil, errors.New("failed to parse root CA PEM")
	}

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: cfg.ServerName,
		RootCAs:    pool,
	}

	if !cfg.EnableMTLS {
		return tlsConf, nil
	}

	clientCert, err := tls.X509KeyPair(cfg.ClientCertPEM, cfg.ClientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client key pair: %w", err)
	}
	tlsConf.Certificates = []tls.Certificate{clientCert}

	return tlsConf, nil
}

func (s *RemoteSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *RemoteSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("digest is empty")
	}
	if opts == nil {
		return nil, errors.New("signer opts is required")
	}

	alg, err := algorithmFromSignerOpts(s.publicKey, opts)
	if err != nil {
		return nil, err
	}

	nonce, err := randomHex(16)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	resp, err := s.client.Sign(ctx, &signrpc.SignRequest{
		KeyID:         s.keyID,
		Algorithm:     alg,
		Digest:        digest,
		TimestampUnix: time.Now().Unix(),
		Nonce:         nonce,
	})
	if err != nil {
		return nil, fmt.Errorf("remote sign request failed: %w", err)
	}

	return resp.Signature, nil
}

func (s *RemoteSigner) Close() error {
	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

func parsePublicKeyFromCert(certPEM []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("invalid certificate PEM")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return parsed.PublicKey, nil
}

func algorithmFromSignerOpts(pub crypto.PublicKey, opts crypto.SignerOpts) (string, error) {
	h := opts.HashFunc()
	if h == 0 {
		return "", errors.New("hash function must be set")
	}

	if _, ok := opts.(*rsa.PSSOptions); ok {
		switch h {
		case crypto.SHA256:
			return signrpc.AlgorithmRSAPSSSHA256, nil
		case crypto.SHA384:
			return signrpc.AlgorithmRSAPSSSHA384, nil
		case crypto.SHA512:
			return signrpc.AlgorithmRSAPSSSHA512, nil
		default:
			return "", fmt.Errorf("unsupported RSA-PSS hash: %v", h)
		}
	}

	switch pub.(type) {
	case *rsa.PublicKey:
		switch h {
		case crypto.SHA256:
			return signrpc.AlgorithmRSAPKCS1v15SHA256, nil
		case crypto.SHA384:
			return signrpc.AlgorithmRSAPKCS1v15SHA384, nil
		case crypto.SHA512:
			return signrpc.AlgorithmRSAPKCS1v15SHA512, nil
		default:
			return "", fmt.Errorf("unsupported RSA hash: %v", h)
		}
	case *ecdsa.PublicKey:
		switch h {
		case crypto.SHA256:
			return signrpc.AlgorithmECDSASHA256, nil
		case crypto.SHA384:
			return signrpc.AlgorithmECDSASHA384, nil
		case crypto.SHA512:
			return signrpc.AlgorithmECDSASHA512, nil
		default:
			return "", fmt.Errorf("unsupported ECDSA hash: %v", h)
		}
	default:
		return "", fmt.Errorf("unsupported public key type: %T", pub)
	}
}

func randomHex(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	return hex.EncodeToString(b), nil
}
