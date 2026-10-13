package lifecycle

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func TestNewManagerRejectsIssuerOutsideValidity(t *testing.T) {
	now := time.Date(2026, time.October, 13, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
	}{
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Hour)},
		{"not yet valid", now.Add(time.Hour), now.Add(2 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, key := issueTestCA(t, tc.notBefore, tc.notAfter)
			store, err := NewDiskStore(t.TempDir(), bytesRepeat(0x42, 32))
			if err != nil {
				t.Fatalf("create store: %v", err)
			}
			_, err = NewManager(ManagerConfig{
				Store: store, IssuerCertPEM: cert, IssuerKeyPEM: key,
				Now: func() time.Time { return now },
			})
			if !errors.Is(err, ErrInvalidCert) {
				t.Fatalf("expected invalid issuer certificate, got %v", err)
			}
		})
	}
}

func TestIssuerExpiryCapsLeafAndBlocksIssuance(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, time.October, 13, 12, 0, 0, 0, time.UTC))
	manager := newManagerWithCAWindow(t, clock, clock.Now().Add(-time.Hour), clock.Now().Add(5*time.Minute))

	bundle, err := manager.IssueIdentity(ctx, "short-ca", ChallengeProof{}, nil)
	if err != nil {
		t.Fatalf("issue identity: %v", err)
	}
	leaf := mustParseLeaf(t, bundle.CertPEM)
	if !leaf.NotAfter.Equal(manager.issuerCert.NotAfter) || !bundle.NotAfter.Equal(leaf.NotAfter) {
		t.Fatalf("leaf and bundle expiry %s / %s must equal CA expiry %s", leaf.NotAfter, bundle.NotAfter, manager.issuerCert.NotAfter)
	}
	if _, err := manager.ValidateIdentity("short-ca", leaf); err != nil {
		t.Fatalf("validate before CA expiry: %v", err)
	}

	clock.Advance(5*time.Minute + time.Second)
	if _, err := manager.IssueIdentity(ctx, "new-ca", ChallengeProof{}, nil); !errors.Is(err, ErrInvalidCert) {
		t.Fatalf("expected issue rejected after CA expiry, got %v", err)
	}
	if _, err := manager.RenewIdentity(ctx, "short-ca"); !errors.Is(err, ErrInvalidCert) {
		t.Fatalf("expected renewal rejected after CA expiry, got %v", err)
	}
	if _, err := manager.ReissueIdentity(ctx, "short-ca", ChallengeProof{}, "rotated"); !errors.Is(err, ErrInvalidCert) {
		t.Fatalf("expected reissue rejected after CA expiry, got %v", err)
	}
	if _, err := manager.ValidateIdentity("short-ca", leaf); !errors.Is(err, ErrInvalidCert) {
		t.Fatalf("expected validation rejected after CA expiry, got %v", err)
	}
}

func TestIssueRejectsIssuerWithNoEncodableLifetime(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, time.October, 13, 12, 0, 0, 0, time.UTC))
	// X.509 certificate validity is encoded with one-second precision.
	manager := newManagerWithCAWindow(t, clock, clock.Now().Add(-time.Hour), clock.Now().Add(100*time.Millisecond))
	if _, err := manager.IssueIdentity(ctx, "no-lifetime", ChallengeProof{}, nil); !errors.Is(err, ErrInvalidCert) {
		t.Fatalf("expected issuance rejection with no encodable lifetime, got %v", err)
	}
}

func TestValidateRejectsLegacyLeafAfterIssuerExpiry(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, time.October, 13, 12, 0, 0, 0, time.UTC))
	manager := newManagerWithCAWindow(t, clock, clock.Now().Add(-time.Hour), clock.Now().Add(2*time.Minute))
	if _, err := manager.IssueIdentity(ctx, "legacy", ChallengeProof{}, nil); err != nil {
		t.Fatalf("issue identity: %v", err)
	}

	// Simulate a certificate created before the fix that outlives its CA.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	uri, err := url.Parse(leaseURIPrefix + "legacy")
	if err != nil {
		t.Fatalf("parse lease URI: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: certCNPrefix + "legacy"},
		NotBefore:             clock.Now().Add(-time.Minute),
		NotAfter:              clock.Now().Add(30 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, manager.issuerCert, &key.PublicKey, manager.issuerKey)
	if err != nil {
		t.Fatalf("sign legacy leaf: %v", err)
	}
	legacy, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse legacy leaf: %v", err)
	}
	state, err := manager.cfg.Store.Load(ctx, "legacy")
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	state.Current.CertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	state.Current.NotAfter = legacy.NotAfter
	if err := manager.cfg.Store.Save(ctx, state); err != nil {
		t.Fatalf("store legacy leaf: %v", err)
	}
	if _, err := manager.ValidateIdentity("legacy", legacy); err != nil {
		t.Fatalf("legacy leaf should validate before CA expiry: %v", err)
	}

	clock.Advance(2*time.Minute + time.Second)
	if !clock.Now().Before(legacy.NotAfter) {
		t.Fatal("test precondition: legacy leaf must still be valid")
	}
	if _, err := manager.ValidateIdentity("legacy", legacy); !errors.Is(err, ErrInvalidCert) {
		t.Fatalf("expected expired issuer rejection despite valid legacy leaf, got %v", err)
	}
}

func newManagerWithCAWindow(t *testing.T, clock *testClock, notBefore, notAfter time.Time) *Manager {
	t.Helper()
	cert, key := issueTestCA(t, notBefore, notAfter)
	store, err := NewDiskStore(t.TempDir(), bytesRepeat(0x43, 32))
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	manager, err := NewManager(ManagerConfig{
		Store: store, IssuerCertPEM: cert, IssuerKeyPEM: key,
		CertTTL: 30 * time.Minute, Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return manager
}
