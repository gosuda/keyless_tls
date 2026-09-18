package signerclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
	headers   func() http.Header
}

func NewRemoteSigner(cfg RemoteSignerConfig, certPEM []byte) (*RemoteSigner, error) {
	cfg.applyDefaults()
	if cfg.Endpoint == "" {
		return nil, errors.New("endpoint is required")
	}
	if cfg.ServerName == "" {
		return nil, errors.New("server name is required")
	}
	if cfg.KeyID == "" {
		return nil, errors.New("key id is required")
	}
	hasCert := len(cfg.ClientCertPEM) > 0
	hasKey := len(cfg.ClientKeyPEM) > 0
	if hasCert != hasKey {
		return nil, errors.New("client certificate and key must both be provided or both be empty")
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

	endpoint, err := signEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
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
		headers:   cfg.Headers,
	}, nil
}

func signerTLSConfig(cfg RemoteSignerConfig) (*tls.Config, error) {
	if cfg.ServerName == "" {
		return nil, errors.New("server name is required")
	}

	hasCert := len(cfg.ClientCertPEM) > 0
	hasKey := len(cfg.ClientKeyPEM) > 0
	if hasCert != hasKey {
		return nil, errors.New("client certificate and key must both be provided or both be empty")
	}

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: cfg.ServerName,
	}

	if len(cfg.RootCAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.RootCAPEM) {
			return nil, errors.New("failed to parse root CA PEM")
		}
		tlsConf.RootCAs = pool
	}

	if hasCert {
		clientCert, err := tls.X509KeyPair(cfg.ClientCertPEM, cfg.ClientKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("load client key pair: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{clientCert}
	}

	return tlsConf, nil
}

func (s *RemoteSigner) KeyID() string {
	return s.keyID
}

func (s *RemoteSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *RemoteSigner) SignTranscript(ctx context.Context, req *signrpc.TranscriptSignRequest) (*signrpc.TranscriptSignResponse, error) {
	if req == nil {
		return nil, errors.New("request is nil")
	}
	if req.KeyID == "" {
		req.KeyID = s.keyID
	}
	if req.Nonce == "" {
		nonce, err := randomHex(16)
		if err != nil {
			return nil, err
		}
		req.Nonce = nonce
	}
	if req.TimestampUnix == 0 {
		req.TimestampUnix = time.Now().Unix()
	}

	reqCtx := ctx
	var cancel context.CancelFunc
	if reqCtx == nil {
		reqCtx = context.Background()
	}
	if s.timeout > 0 {
		reqCtx, cancel = context.WithTimeout(reqCtx, s.timeout)
		defer cancel()
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode transcript sign request: %w", err)
	}

	// signEndpoint already resolves to the single /v1/sign endpoint, whose
	// wire contract is the transcript-bound one.
	url := s.endpoint

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("build transcript sign request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if s.headers != nil {
		for key, values := range s.headers() {
			httpReq.Header.Del(key)
			for _, value := range values {
				httpReq.Header.Add(key, value)
			}
		}
	}

	httpResp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("remote transcript sign request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		var errResp signrpc.ErrorResponse
		if decodeErr := json.NewDecoder(httpResp.Body).Decode(&errResp); decodeErr == nil && errResp.Error != "" {
			return nil, fmt.Errorf("remote transcript sign request failed: %s", errResp.Error)
		}
		return nil, fmt.Errorf("remote transcript sign request failed: http %d", httpResp.StatusCode)
	}

	var resp signrpc.TranscriptSignResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode transcript sign response: %w", err)
	}

	return &resp, nil
}

func (s *RemoteSigner) Close() error {
	if s.client == nil {
		return nil
	}
	s.client.CloseIdleConnections()
	return nil
}

func signEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", errors.New("endpoint is required")
	}

	if strings.HasPrefix(endpoint, "https://") || strings.HasPrefix(endpoint, "http://") {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return "", fmt.Errorf("invalid endpoint: %w", err)
		}
		if parsed.Scheme != "https" {
			return "", fmt.Errorf("endpoint must use https scheme: %s", parsed.Scheme)
		}
		if parsed.User != nil {
			return "", errors.New("endpoint must not include user info")
		}
		if parsed.Path != "" && parsed.Path != "/" {
			return "", errors.New("endpoint must not include a path")
		}
		if parsed.RawQuery != "" || parsed.Fragment != "" {
			return "", errors.New("endpoint must not include query or fragment")
		}
		if parsed.Host == "" {
			return "", errors.New("invalid endpoint host")
		}
		return strings.TrimRight("https://"+parsed.Host, "/") + signrpc.SignPath, nil
	}

	if strings.ContainsAny(endpoint, "/?#") {
		return "", errors.New("endpoint must not include URL path, query, or fragment")
	}

	return "https://" + strings.TrimRight(endpoint, "/") + signrpc.SignPath, nil
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

func randomHex(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	return hex.EncodeToString(b), nil
}
