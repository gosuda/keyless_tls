package lifecycle

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

func TestNewManagerRejectsIssuerOutsideValidity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
	}{
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Minute)},
		{"not yet valid", now.Add(time.Minute), now.Add(2 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			certPEM, keyPEM := issueTestCA(t, tc.notBefore, tc.notAfter)
			store, err := NewDiskStore(t.TempDir(), bytesRepeat(0x41, 32))
			if err != nil {
				t.Fatalf("create disk store: %v", err)
			}
			_, err = NewManager(ManagerConfig{
				Store:         store,
				IssuerCertPEM: certPEM,
				IssuerKeyPEM:  keyPEM,
				Now:           func() time.Time { return now },
			})
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected invalid issuer time to be rejected, got %v", err)
			}
		})
	}
}

func TestIssueAndRenewCapLeafToIssuerValidity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(now)
	issuerNotBefore := now.Add(-20 * time.Second)
	issuerNotAfter := now.Add(5 * time.Minute)
	manager := newIssuerWindowManager(t, clock, issuerNotBefore, issuerNotAfter)

	ctx := context.Background()
	issued, err := manager.IssueIdentity(ctx, "lease-short", ChallengeProof{}, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	leaf := mustParseLeaf(t, issued.CertPEM)
	if !leaf.NotBefore.Equal(issuerNotBefore) || !leaf.NotAfter.Equal(issuerNotAfter) {
		t.Fatalf("leaf validity [%v, %v] exceeds issuer [%v, %v]", leaf.NotBefore, leaf.NotAfter, issuerNotBefore, issuerNotAfter)
	}
	if !issued.NotBefore.Equal(leaf.NotBefore) || !issued.NotAfter.Equal(leaf.NotAfter) {
		t.Fatalf("bundle validity does not match issued leaf")
	}
	if _, err := manager.ValidateIdentity("lease-short", leaf); err != nil {
		t.Fatalf("validate issued leaf: %v", err)
	}

	clock.Advance(2 * time.Minute)
	renewed, err := manager.RenewIdentity(ctx, "lease-short")
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if got := mustParseLeaf(t, renewed.CertPEM).NotAfter; !got.Equal(issuerNotAfter) {
		t.Fatalf("renewed leaf expiry = %v, want %v", got, issuerNotAfter)
	}
}

func TestIssuerExpiryStopsIssuanceAndValidation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(now)
	manager := newIssuerWindowManager(t, clock, now.Add(-time.Hour), now.Add(2*time.Minute))
	ctx := context.Background()
	issued, err := manager.IssueIdentity(ctx, "lease-expiry", ChallengeProof{}, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	clock.Advance(2 * time.Minute)
	if _, err := manager.IssueIdentity(ctx, "lease-boundary", ChallengeProof{}, nil); !errors.Is(err, ErrInvalidCert) {
		t.Fatalf("expected rejection at issuer expiry boundary, got %v", err)
	}
	clock.Advance(time.Second)
	if _, err := manager.IssueIdentity(ctx, "lease-late", ChallengeProof{}, nil); !errors.Is(err, ErrInvalidCert) {
		t.Fatalf("expected expired issuer to block issuance, got %v", err)
	}
	if _, err := manager.RenewIdentity(ctx, "lease-expiry"); !errors.Is(err, ErrInvalidCert) {
		t.Fatalf("expected expired issuer to block renewal, got %v", err)
	}
	if _, err := manager.ReissueIdentity(ctx, "lease-expiry", ChallengeProof{}, "rotate"); !errors.Is(err, ErrInvalidCert) {
		t.Fatalf("expected expired issuer to block reissue, got %v", err)
	}
	if _, err := manager.ValidateIdentity("lease-expiry", mustParseLeaf(t, issued.CertPEM)); !errors.Is(err, ErrInvalidCert) {
		t.Fatalf("expected expired issuer to block validation, got %v", err)
	}
}

func TestValidateRejectsStoredLeafSignedByExpiredIssuer(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(now)
	manager := newIssuerWindowManager(t, clock, now.Add(-time.Hour), now.Add(2*time.Minute))
	ctx := context.Background()
	bundle, err := manager.IssueIdentity(ctx, "lease-legacy", ChallengeProof{}, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Simulate a stored leaf issued before this fix with a lifetime beyond its issuer.
	leaf := mustParseLeaf(t, bundle.CertPEM)
	legacyTemplate := *leaf
	legacyTemplate.NotAfter = manager.issuerCert.NotAfter.Add(10 * time.Minute)
	der, err := x509.CreateCertificate(rand.Reader, &legacyTemplate, manager.issuerCert, leaf.PublicKey, manager.issuerKey)
	if err != nil {
		t.Fatalf("create legacy leaf: %v", err)
	}
	legacyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	state, err := manager.cfg.Store.Load(ctx, "lease-legacy")
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	state.Current.CertPEM = legacyPEM
	if err := manager.cfg.Store.Save(ctx, state); err != nil {
		t.Fatalf("save legacy state: %v", err)
	}

	clock.Advance(3 * time.Minute)
	legacyLeaf := mustParseLeaf(t, legacyPEM)
	if clock.Now().After(legacyLeaf.NotAfter) {
		t.Fatal("legacy leaf must be within its own validity window")
	}
	if _, err := manager.ValidateIdentity("lease-legacy", legacyLeaf); !errors.Is(err, ErrInvalidCert) {
		t.Fatalf("expected expired issuer to invalidate legacy leaf, got %v", err)
	}
}

func newIssuerWindowManager(t *testing.T, clock *testClock, notBefore, notAfter time.Time) *Manager {
	t.Helper()
	issuerCertPEM, issuerKeyPEM := issueTestCA(t, notBefore, notAfter)
	store, err := NewDiskStore(t.TempDir(), bytesRepeat(0x41, 32))
	if err != nil {
		t.Fatalf("create disk store: %v", err)
	}
	manager, err := NewManager(ManagerConfig{
		Store:         store,
		IssuerCertPEM: issuerCertPEM,
		IssuerKeyPEM:  issuerKeyPEM,
		CertTTL:       30 * time.Minute,
		Now:           clock.Now,
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return manager
}
