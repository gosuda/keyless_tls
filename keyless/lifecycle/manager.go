package lifecycle

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// CapabilityVersion is used by callers to gate lifecycle compatibility.
	CapabilityVersion = 1

	certCNPrefix   = "lease:"
	leaseURIPrefix = "spiffe://portal/lease/"

	defaultCertTTL       = 24 * time.Hour
	defaultOverlapGrace  = 10 * time.Minute
	defaultReissueWindow = 30 * time.Second
)

var (
	ErrInvalidRequest    = errors.New("invalid request")
	ErrInvalidLeaseID    = errors.New("invalid lease id")
	ErrLeaseNotFound     = errors.New("lease identity not found")
	ErrIdentityExists    = errors.New("lease identity already exists")
	ErrCorruptStore      = errors.New("identity store is corrupted")
	ErrChallengeRequired = errors.New("challenge proof is required")
	ErrChallengeRejected = errors.New("challenge proof rejected")
	ErrReissueRateLimit  = errors.New("reissue rate limited")
	ErrInvalidCert       = errors.New("invalid certificate")
	ErrLeaseMismatch     = errors.New("certificate lease mismatch")
	ErrOverlapExpired    = errors.New("certificate overlap window expired")
)

type ChallengeProof struct {
	Nonce string `json:"nonce"`
	Token string `json:"token"`
}

type ChallengeValidator interface {
	ValidateChallenge(ctx context.Context, leaseID string, proof ChallengeProof) error
}

type ManagerConfig struct {
	Store            Store
	IssuerCertPEM    []byte
	IssuerKeyPEM     []byte
	CertTTL          time.Duration
	OverlapGrace     time.Duration
	ReissueMinPeriod time.Duration
	RequireChallenge bool
	Validator        ChallengeValidator
	Now              func() time.Time
	Rand             io.Reader
}

type Manager struct {
	cfg         ManagerConfig
	issuerCert  *x509.Certificate
	issuerKey   crypto.Signer
	issuerChain []byte

	mu         sync.Mutex
	reissuedAt map[string]time.Time
}

type IdentityBundle struct {
	LeaseID   string            `json:"lease_id"`
	CertPEM   []byte            `json:"cert_pem"`
	KeyPEM    []byte            `json:"key_pem"`
	ChainPEM  []byte            `json:"chain_pem"`
	Epoch     int               `json:"epoch"`
	NotBefore time.Time         `json:"not_before"`
	NotAfter  time.Time         `json:"not_after"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type ValidationResult struct {
	LeaseID    string `json:"lease_id"`
	Epoch      int    `json:"epoch"`
	UsingPrior bool   `json:"using_prior"`
}

type leaseState struct {
	LeaseID            string          `json:"lease_id"`
	Current            IdentityBundle  `json:"current"`
	Previous           *IdentityBundle `json:"previous,omitempty"`
	PreviousValidUntil time.Time       `json:"previous_valid_until,omitempty"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidRequest)
	}
	if len(cfg.IssuerCertPEM) == 0 {
		return nil, fmt.Errorf("%w: issuer certificate is required", ErrInvalidRequest)
	}
	if len(cfg.IssuerKeyPEM) == 0 {
		return nil, fmt.Errorf("%w: issuer private key is required", ErrInvalidRequest)
	}
	if cfg.CertTTL <= 0 {
		cfg.CertTTL = defaultCertTTL
	}
	if cfg.OverlapGrace < 0 {
		return nil, fmt.Errorf("%w: overlap grace cannot be negative", ErrInvalidRequest)
	}
	if cfg.OverlapGrace == 0 {
		cfg.OverlapGrace = defaultOverlapGrace
	}
	if cfg.ReissueMinPeriod < 0 {
		return nil, fmt.Errorf("%w: reissue min period cannot be negative", ErrInvalidRequest)
	}
	if cfg.ReissueMinPeriod == 0 {
		cfg.ReissueMinPeriod = defaultReissueWindow
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}

	issuerCert, err := parseLeafCertPEM(cfg.IssuerCertPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: parse issuer cert: %v", ErrInvalidRequest, err)
	}
	issuerKey, err := parseSignerPEM(cfg.IssuerKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: parse issuer key: %v", ErrInvalidRequest, err)
	}

	chain := append([]byte(nil), cfg.IssuerCertPEM...)
	return &Manager{
		cfg:         cfg,
		issuerCert:  issuerCert,
		issuerKey:   issuerKey,
		issuerChain: chain,
		reissuedAt:  make(map[string]time.Time),
	}, nil
}

func (m *Manager) IssueIdentity(ctx context.Context, leaseID string, proof ChallengeProof, metadata map[string]string) (*IdentityBundle, error) {
	leaseID = normalizeLeaseID(leaseID)
	if leaseID == "" {
		return nil, ErrInvalidLeaseID
	}
	if err := m.validateChallenge(ctx, leaseID, proof); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	existing, err := m.cfg.Store.Load(ctx, leaseID)
	if err != nil && !errors.Is(err, ErrLeaseNotFound) {
		return nil, err
	}
	now := m.cfg.Now()
	if existing != nil && now.Before(existing.Current.NotAfter) {
		return nil, ErrIdentityExists
	}
	epoch := 1
	if existing != nil && existing.Current.Epoch > 0 {
		epoch = existing.Current.Epoch + 1
	}
	current, err := m.issueBundleLocked(leaseID, epoch, metadata, now)
	if err != nil {
		return nil, err
	}

	state := &leaseState{
		LeaseID:   leaseID,
		Current:   current,
		UpdatedAt: now,
	}
	if err := m.cfg.Store.Save(ctx, state); err != nil {
		return nil, err
	}
	bundle := copyBundle(current)
	return &bundle, nil
}

func (m *Manager) LoadIdentity(ctx context.Context, leaseID string) (*IdentityBundle, error) {
	leaseID = normalizeLeaseID(leaseID)
	if leaseID == "" {
		return nil, ErrInvalidLeaseID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.cfg.Store.Load(ctx, leaseID)
	if err != nil {
		return nil, err
	}
	bundle := copyBundle(state.Current)
	return &bundle, nil
}

func (m *Manager) RenewIdentity(ctx context.Context, leaseID string) (*IdentityBundle, error) {
	leaseID = normalizeLeaseID(leaseID)
	if leaseID == "" {
		return nil, ErrInvalidLeaseID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.cfg.Store.Load(ctx, leaseID)
	if err != nil {
		return nil, err
	}
	now := m.cfg.Now()
	if now.After(state.Current.NotAfter) {
		return nil, ErrInvalidCert
	}
	renewed, err := m.issueBundleLocked(leaseID, state.Current.Epoch+1, state.Current.Metadata, now)
	if err != nil {
		return nil, err
	}

	previous := copyBundle(state.Current)
	state.Previous = &previous
	state.PreviousValidUntil = now.Add(m.cfg.OverlapGrace)
	state.Current = renewed
	state.UpdatedAt = now
	if err := m.cfg.Store.Save(ctx, state); err != nil {
		return nil, err
	}
	bundle := copyBundle(renewed)
	return &bundle, nil
}

func (m *Manager) ReissueIdentity(ctx context.Context, leaseID string, proof ChallengeProof, _ string) (*IdentityBundle, error) {
	leaseID = normalizeLeaseID(leaseID)
	if leaseID == "" {
		return nil, ErrInvalidLeaseID
	}
	if err := m.validateChallenge(ctx, leaseID, proof); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.cfg.Now()
	if last, ok := m.reissuedAt[leaseID]; ok && now.Sub(last) < m.cfg.ReissueMinPeriod {
		return nil, ErrReissueRateLimit
	}

	state, err := m.cfg.Store.Load(ctx, leaseID)
	if err != nil && !errors.Is(err, ErrLeaseNotFound) {
		return nil, err
	}
	epoch := 1
	metadata := map[string]string(nil)
	var previous *IdentityBundle
	if state != nil {
		epoch = state.Current.Epoch + 1
		metadata = state.Current.Metadata
		prev := copyBundle(state.Current)
		previous = &prev
	}

	reissued, err := m.issueBundleLocked(leaseID, epoch, metadata, now)
	if err != nil {
		return nil, err
	}
	if state == nil {
		state = &leaseState{LeaseID: leaseID}
	}
	state.Current = reissued
	state.Previous = previous
	if previous != nil {
		state.PreviousValidUntil = now.Add(m.cfg.OverlapGrace)
	}
	state.UpdatedAt = now
	if err := m.cfg.Store.Save(ctx, state); err != nil {
		return nil, err
	}
	m.reissuedAt[leaseID] = now
	bundle := copyBundle(reissued)
	return &bundle, nil
}

func (m *Manager) ValidateIdentity(leaseID string, peerCert *x509.Certificate) (*ValidationResult, error) {
	leaseID = normalizeLeaseID(leaseID)
	if leaseID == "" {
		return nil, ErrInvalidLeaseID
	}
	if peerCert == nil {
		return nil, ErrInvalidCert
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.cfg.Store.Load(context.Background(), leaseID)
	if err != nil {
		return nil, err
	}
	now := m.cfg.Now()
	if err := m.validatePeerCert(leaseID, peerCert, now); err != nil {
		return nil, err
	}

	currentLeaf, err := parseLeafCertPEM(state.Current.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: parse current cert: %v", ErrCorruptStore, err)
	}
	if certEqual(currentLeaf.Raw, peerCert.Raw) {
		return &ValidationResult{
			LeaseID: leaseID,
			Epoch:   state.Current.Epoch,
		}, nil
	}

	if state.Previous != nil {
		prevLeaf, err := parseLeafCertPEM(state.Previous.CertPEM)
		if err != nil {
			return nil, fmt.Errorf("%w: parse previous cert: %v", ErrCorruptStore, err)
		}
		if certEqual(prevLeaf.Raw, peerCert.Raw) {
			if now.After(state.PreviousValidUntil) {
				return nil, ErrOverlapExpired
			}
			return &ValidationResult{
				LeaseID:    leaseID,
				Epoch:      state.Previous.Epoch,
				UsingPrior: true,
			}, nil
		}
	}

	return nil, ErrLeaseMismatch
}

func (m *Manager) validateChallenge(ctx context.Context, leaseID string, proof ChallengeProof) error {
	if !m.cfg.RequireChallenge {
		return nil
	}
	if strings.TrimSpace(proof.Nonce) == "" || strings.TrimSpace(proof.Token) == "" {
		return ErrChallengeRequired
	}
	if m.cfg.Validator == nil {
		return ErrChallengeRejected
	}
	if err := m.cfg.Validator.ValidateChallenge(ctx, leaseID, proof); err != nil {
		return fmt.Errorf("%w: %v", ErrChallengeRejected, err)
	}
	return nil
}

func (m *Manager) issueBundleLocked(leaseID string, epoch int, metadata map[string]string, now time.Time) (IdentityBundle, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), m.cfg.Rand)
	if err != nil {
		return IdentityBundle{}, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(m.cfg.Rand, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return IdentityBundle{}, fmt.Errorf("generate serial: %w", err)
	}
	leaseURI, err := url.Parse(leaseURIPrefix + leaseID)
	if err != nil {
		return IdentityBundle{}, fmt.Errorf("build lease URI: %w", err)
	}

	notBefore := now.Add(-1 * time.Minute)
	notAfter := now.Add(m.cfg.CertTTL)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: certCNPrefix + leaseID,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{leaseURI},
	}

	der, err := x509.CreateCertificate(m.cfg.Rand, template, m.issuerCert, &priv.PublicKey, m.issuerKey)
	if err != nil {
		return IdentityBundle{}, fmt.Errorf("create cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return IdentityBundle{}, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	chain := append([]byte(nil), certPEM...)
	chain = append(chain, m.issuerChain...)

	return IdentityBundle{
		LeaseID:   leaseID,
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		ChainPEM:  chain,
		Epoch:     epoch,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		Metadata:  copyMetadata(metadata),
	}, nil
}

func (m *Manager) validatePeerCert(leaseID string, cert *x509.Certificate, now time.Time) error {
	if cert == nil {
		return ErrInvalidCert
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return ErrInvalidCert
	}
	if err := cert.CheckSignatureFrom(m.issuerCert); err != nil {
		return ErrInvalidCert
	}
	if len(cert.ExtKeyUsage) > 0 {
		hasClientAuth := false
		for _, usage := range cert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageClientAuth {
				hasClientAuth = true
				break
			}
		}
		if !hasClientAuth {
			return ErrInvalidCert
		}
	}

	certLeaseID := extractLeaseIDFromCert(cert)
	if certLeaseID == "" {
		return ErrLeaseMismatch
	}
	if subtle.ConstantTimeCompare([]byte(leaseID), []byte(certLeaseID)) != 1 {
		return ErrLeaseMismatch
	}
	return nil
}

func extractLeaseIDFromCert(cert *x509.Certificate) string {
	for _, uri := range cert.URIs {
		if uri == nil {
			continue
		}
		value := strings.TrimSpace(uri.String())
		if strings.HasPrefix(value, leaseURIPrefix) {
			return strings.TrimPrefix(value, leaseURIPrefix)
		}
	}
	commonName := strings.TrimSpace(cert.Subject.CommonName)
	if strings.HasPrefix(commonName, certCNPrefix) {
		return strings.TrimPrefix(commonName, certCNPrefix)
	}
	return ""
}

func normalizeLeaseID(leaseID string) string {
	return strings.TrimSpace(leaseID)
}

func copyBundle(bundle IdentityBundle) IdentityBundle {
	return IdentityBundle{
		LeaseID:   bundle.LeaseID,
		CertPEM:   append([]byte(nil), bundle.CertPEM...),
		KeyPEM:    append([]byte(nil), bundle.KeyPEM...),
		ChainPEM:  append([]byte(nil), bundle.ChainPEM...),
		Epoch:     bundle.Epoch,
		NotBefore: bundle.NotBefore,
		NotAfter:  bundle.NotAfter,
		Metadata:  copyMetadata(bundle.Metadata),
	}
}

func copyMetadata(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func certEqual(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 || len(a) != len(b) {
		return false
	}
	hashA := sha256.Sum256(a)
	hashB := sha256.Sum256(b)
	return subtle.ConstantTimeCompare(hashA[:], hashB[:]) == 1
}

func parseLeafCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func parseSignerPEM(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("invalid private key pem")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key format")
}
