package t13server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/gosuda/keyless_tls/relay/signrpc"
)

type TranscriptSigner interface {
	SignTranscript(ctx context.Context, req *signrpc.TranscriptSignRequest) (*signrpc.TranscriptSignResponse, error)
}

type ConnectionState = tls.ConnectionState

type Config struct {
	// Certificates is the raw DER certificate chain. The first is the leaf.
	Certificates [][]byte
	// CertPEM is optional; if Certificates is empty, it will be parsed from CertPEM.
	CertPEM []byte
	// NextProtos is the list of supported ALPN protocols (e.g. "h2", "http/1.1").
	NextProtos []string
	// KeyID is the signer key identifier to send in TranscriptSignRequest.
	KeyID string
	// TranscriptSigner performs remote transcript-bound signing.
	TranscriptSigner TranscriptSigner
	// HandshakeTimeout is the maximum duration allowed for the TLS handshake. Defaults to 10s.
	HandshakeTimeout time.Duration
}

type Server struct {
	cfg Config

	sigScheme uint16
	sigAlg    string
}

func NewServer(cfg Config) (*Server, error) {
	if len(cfg.Certificates) == 0 && len(cfg.CertPEM) > 0 {
		ders, err := parseCertificatesFromPEM(cfg.CertPEM)
		if err != nil {
			return nil, fmt.Errorf("parse cert pem: %w", err)
		}
		cfg.Certificates = ders
	}
	if len(cfg.Certificates) == 0 {
		return nil, errors.New("at least one certificate is required")
	}
	if cfg.TranscriptSigner == nil {
		return nil, errors.New("transcript signer is required")
	}

	leaf, err := x509.ParseCertificate(cfg.Certificates[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}

	scheme, alg, err := determineSignatureScheme(leaf.PublicKey)
	if err != nil {
		return nil, err
	}

	// Validate the full chain eagerly; the parsed form is not needed afterwards.
	for _, der := range cfg.Certificates {
		if _, err := x509.ParseCertificate(der); err != nil {
			return nil, fmt.Errorf("parse certificate chain: %w", err)
		}
	}

	if len(cfg.NextProtos) == 0 {
		cfg.NextProtos = []string{"http/1.1"}
	}

	return &Server{
		cfg:       cfg,
		sigScheme: scheme,
		sigAlg:    alg,
	}, nil
}

func (s *Server) NewConn(raw net.Conn, binding []byte) *Conn {
	timeout := s.cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return newConn(raw, binding, s, timeout)
}

func (s *Server) ServeConn(ctx context.Context, raw net.Conn, binding []byte) (*Conn, error) {
	if raw == nil {
		return nil, errors.New("raw connection is nil")
	}
	conn := s.NewConn(raw, binding)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

func parseCertificatesFromPEM(pemBytes []byte) ([][]byte, error) {
	var certs [][]byte
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate blocks found in PEM")
	}
	return certs, nil
}

func determineSignatureScheme(pub any) (uint16, string, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return SignatureSchemeECDSAP256SHA256, signrpc.AlgorithmECDSASHA256, nil
		}
		return 0, "", fmt.Errorf("unsupported ECDSA curve: %v", k.Curve.Params().Name)
	case *rsa.PublicKey:
		return SignatureSchemeRSAPSSSHA256, signrpc.AlgorithmRSAPSSSHA256, nil
	case ed25519.PublicKey:
		return SignatureSchemeEd25519, signrpc.AlgorithmEd25519, nil
	default:
		return 0, "", fmt.Errorf("unsupported public key type: %T", pub)
	}
}
