package lifecycle

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrLeaseNotFound  = errors.New("lease not found")
	ErrLeaseConflict  = errors.New("lease conflict")
	ErrLeaseExpired   = errors.New("lease expired")
	ErrLeaseMismatch  = errors.New("lease mismatch")
	ErrInvalidRequest = errors.New("invalid request")
	ErrLeaseCorrupted = errors.New("lease state is corrupted")
)

type ManagerConfig struct {
	Store        Store
	OverlapGrace time.Duration
	Now          func() time.Time
}

type Manager struct {
	store        Store
	overlapGrace time.Duration
	now          func() time.Time
	mu           sync.Mutex
}

type Lease struct {
	LeaseID             string        `json:"lease_id"`
	KeyID               string        `json:"key_id"`
	BoundTo             string        `json:"bound_to"`
	CertPEM             []byte        `json:"cert_pem"`
	CertFingerprint     string        `json:"fingerprint"`
	IssuedAt            time.Time     `json:"issued_at"`
	NotBefore           time.Time     `json:"not_before"`
	NotAfter            time.Time     `json:"not_after"`
	OverlapGrace        time.Duration `json:"overlap_grace"`
	PreviousFingerprint string        `json:"previous_fingerprint,omitempty"`
	PreviousValidUntil  time.Time     `json:"previous_valid_until,omitempty"`
}

func (l *Lease) Active(now time.Time) bool {
	if l == nil {
		return false
	}
	if now.Before(l.NotBefore) {
		return false
	}
	return now.Before(l.NotAfter.Add(l.OverlapGrace))
}

func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidRequest)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Manager{
		store:        cfg.Store,
		overlapGrace: cfg.OverlapGrace,
		now:          cfg.Now,
	}, nil
}

type IssueRequest struct {
	KeyID   string
	LeaseID string
	CertPEM []byte
	BoundTo string
}

type RenewRequest struct {
	KeyID   string
	CertPEM []byte
	BoundTo string
}

type ReissueRequest struct {
	KeyID   string
	LeaseID string
	CertPEM []byte
	BoundTo string
}

type ValidateRequest struct {
	KeyID   string
	CertPEM []byte
	BoundTo string
}

func (m *Manager) Issue(ctx context.Context, req IssueRequest) (*Lease, error) {
	state, err := m.prepareState(req.KeyID, req.CertPEM, req.BoundTo, req.LeaseID)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, err := m.store.Load(ctx, req.KeyID)
	if err != nil && !errors.Is(err, ErrLeaseNotFound) {
		return nil, err
	}
	if existing != nil && existing.Active(m.now()) {
		return nil, ErrLeaseConflict
	}
	if err := m.store.Save(ctx, state); err != nil {
		return nil, err
	}
	return state.toLease(), nil
}

func (m *Manager) Renew(ctx context.Context, req RenewRequest) (*Lease, error) {
	if req.KeyID == "" {
		return nil, fmt.Errorf("%w: key id is required", ErrInvalidRequest)
	}
	state, err := m.prepareState(req.KeyID, req.CertPEM, req.BoundTo, "")
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, err := m.loadState(ctx, req.KeyID)
	if err != nil {
		return nil, err
	}
	if !existing.Active(m.now()) {
		return nil, fmt.Errorf("%w: existing lease is no longer active", ErrLeaseExpired)
	}
	if err := m.enforceBound(existing, state); err != nil {
		return nil, err
	}
	state.LeaseID = existing.LeaseID
	state.PreviousFingerprint = existing.CertFingerprint
	state.PreviousValidUntil = m.now().Add(m.overlapGrace)
	state.OverlapGrace = m.overlapGrace
	if err := m.store.Save(ctx, state); err != nil {
		return nil, err
	}
	return state.toLease(), nil
}

func (m *Manager) Reissue(ctx context.Context, req ReissueRequest) (*Lease, error) {
	state, err := m.prepareState(req.KeyID, req.CertPEM, req.BoundTo, req.LeaseID)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, err := m.store.Load(ctx, req.KeyID)
	if err != nil && !errors.Is(err, ErrLeaseNotFound) {
		return nil, err
	}
	if existing != nil && existing.Active(m.now()) {
		return nil, ErrLeaseConflict
	}
	if existing != nil {
		state.PreviousFingerprint = existing.CertFingerprint
		state.PreviousValidUntil = m.now().Add(m.overlapGrace)
	} else {
		state.PreviousFingerprint = ""
	}
	if err := m.store.Save(ctx, state); err != nil {
		return nil, err
	}
	return state.toLease(), nil
}

func (m *Manager) Load(ctx context.Context, keyID string) (*Lease, error) {
	state, err := m.store.Load(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return state.toLease(), nil
}

func (m *Manager) Validate(ctx context.Context, req ValidateRequest) (*Lease, error) {
	state, err := m.store.Load(ctx, req.KeyID)
	if err != nil {
		return nil, err
	}
	cert, err := parseCertificate(req.CertPEM)
	if err != nil {
		return nil, err
	}
	if req.BoundTo != "" && req.BoundTo != state.BoundTo {
		return nil, ErrLeaseMismatch
	}
	now := m.now()
	if now.Before(state.NotBefore) || now.After(state.NotAfter.Add(state.OverlapGrace)) {
		return nil, ErrLeaseExpired
	}
	fp := fingerprint(cert)
	if fp == state.CertFingerprint {
		return state.toLease(), nil
	}
	if state.PreviousFingerprint != "" && fp == state.PreviousFingerprint && now.Before(state.PreviousValidUntil) {
		return state.toLease(), nil
	}
	return nil, ErrLeaseMismatch
}

func (m *Manager) prepareState(keyID string, certPEM []byte, boundTo, leaseID string) (*leaseState, error) {
	if keyID == "" {
		return nil, fmt.Errorf("%w: key id is required", ErrInvalidRequest)
	}
	if len(certPEM) == 0 {
		return nil, fmt.Errorf("%w: certificate is required", ErrInvalidRequest)
	}
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return nil, err
	}
	if cert.NotAfter.Before(cert.NotBefore) {
		return nil, fmt.Errorf("%w: certificate not-after precedes not-before", ErrInvalidRequest)
	}
	if leaseID == "" {
		leaseID, err = randomHex(16)
		if err != nil {
			return nil, err
		}
	}
	now := m.now()
	return &leaseState{
		LeaseID:         leaseID,
		KeyID:           keyID,
		BoundTo:         boundTo,
		CertPEM:         append([]byte(nil), certPEM...),
		CertFingerprint: fingerprint(cert),
		IssuedAt:        now,
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
		OverlapGrace:    m.overlapGrace,
	}, nil
}

func (m *Manager) loadState(ctx context.Context, keyID string) (*leaseState, error) {
	state, err := m.store.Load(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return state, nil
}

func parseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: invalid certificate PEM", ErrInvalidRequest)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return cert, nil
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func randomHex(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type leaseState struct {
	LeaseID             string        `json:"lease_id"`
	KeyID               string        `json:"key_id"`
	BoundTo             string        `json:"bound_to"`
	CertPEM             []byte        `json:"cert_pem"`
	CertFingerprint     string        `json:"fingerprint"`
	IssuedAt            time.Time     `json:"issued_at"`
	NotBefore           time.Time     `json:"not_before"`
	NotAfter            time.Time     `json:"not_after"`
	OverlapGrace        time.Duration `json:"overlap_grace"`
	PreviousFingerprint string        `json:"previous_fingerprint,omitempty"`
	PreviousValidUntil  time.Time     `json:"previous_valid_until,omitempty"`
}

func (s *leaseState) toLease() *Lease {
	if s == nil {
		return nil
	}
	cp := append([]byte(nil), s.CertPEM...)
	return &Lease{
		LeaseID:             s.LeaseID,
		KeyID:               s.KeyID,
		BoundTo:             s.BoundTo,
		CertPEM:             cp,
		CertFingerprint:     s.CertFingerprint,
		IssuedAt:            s.IssuedAt,
		NotBefore:           s.NotBefore,
		NotAfter:            s.NotAfter,
		OverlapGrace:        s.OverlapGrace,
		PreviousFingerprint: s.PreviousFingerprint,
		PreviousValidUntil:  s.PreviousValidUntil,
	}
}

func (s *leaseState) Active(now time.Time) bool {
	if s == nil {
		return false
	}
	if now.Before(s.NotBefore) {
		return false
	}
	return now.Before(s.NotAfter.Add(s.OverlapGrace))
}

func (m *Manager) enforceBound(existing, incoming *leaseState) error {
	if existing == nil || incoming == nil {
		return nil
	}
	if existing.BoundTo == "" || incoming.BoundTo == "" || existing.BoundTo == incoming.BoundTo {
		return nil
	}
	return ErrLeaseMismatch
}
