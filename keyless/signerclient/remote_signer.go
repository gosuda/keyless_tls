package signerclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gosuda/keyless_tls/relay/signrpc"
)

type RemoteSigner struct {
	keyID     string
	publicKey crypto.PublicKey
	endpoint  string
	client    *http.Client
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

	endpoint := signEndpoint(cfg.Endpoint)
	transport := &http.Transport{
		TLSClientConfig:     tlsConf,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	client := &http.Client{Transport: transport}

	return &RemoteSigner{
		keyID:     cfg.KeyID,
		publicKey: pub,
		endpoint:  endpoint,
		client:    client,
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

	reqBody, err := json.Marshal(&signrpc.SignRequest{
		KeyID:         s.keyID,
		Algorithm:     alg,
		Digest:        digest,
		TimestampUnix: time.Now().Unix(),
		Nonce:         nonce,
	})
	if err != nil {
		return nil, fmt.Errorf("encode sign request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("build sign request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	httpResp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("remote sign request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		var errResp signrpc.ErrorResponse
		if decodeErr := json.NewDecoder(httpResp.Body).Decode(&errResp); decodeErr == nil && errResp.Error != "" {
			return nil, fmt.Errorf("remote sign request failed: %s", errResp.Error)
		}
		return nil, fmt.Errorf("remote sign request failed: http %d", httpResp.StatusCode)
	}

	var resp signrpc.SignResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode sign response: %w", err)
	}

	return resp.Signature, nil
}

func (s *RemoteSigner) Close() error {
	if s.client == nil {
		return nil
	}
	s.client.CloseIdleConnections()
	return nil
}

func signEndpoint(endpoint string) string {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return strings.TrimRight(endpoint, "/") + signrpc.SignPath
	}
	return "https://" + strings.TrimRight(endpoint, "/") + signrpc.SignPath
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
