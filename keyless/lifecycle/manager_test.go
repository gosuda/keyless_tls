package lifecycle

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestManagerLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()
	store, err := NewDiskStore(dir, bytesRepeat(0x42, 32))
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	clock := newTestClock(time.Now().UTC())
	manager, err := NewManager(ManagerConfig{
		Store:        store,
		OverlapGrace: 2 * time.Minute,
		Now:          clock.Now,
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	cert1 := generateCert(t, clock.Now().Add(-time.Minute), clock.Now().Add(10*time.Minute))
	lease1, err := manager.Issue(ctx, IssueRequest{
		KeyID:   "node-a",
		CertPEM: cert1,
		BoundTo: "app-alpha",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	loaded, err := manager.Load(ctx, "node-a")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.LeaseID != lease1.LeaseID {
		t.Fatalf("lease id mismatch: got=%s want=%s", loaded.LeaseID, lease1.LeaseID)
	}

	if _, err := manager.Validate(ctx, ValidateRequest{KeyID: "node-a", CertPEM: cert1}); err != nil {
		t.Fatalf("validate issued cert: %v", err)
	}

	if _, err := manager.Issue(ctx, IssueRequest{KeyID: "node-a", CertPEM: cert1}); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("expected issue conflict, got: %v", err)
	}

	clock.Advance(9 * time.Minute)
	cert2 := generateCert(t, clock.Now().Add(-time.Second), clock.Now().Add(20*time.Minute))
	renewed, err := manager.Renew(ctx, RenewRequest{
		KeyID:   "node-a",
		CertPEM: cert2,
		BoundTo: "app-alpha",
	})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if renewed.LeaseID != lease1.LeaseID {
		t.Fatalf("renew should keep lease id")
	}

	clock.Advance(30 * time.Second)
	if _, err := manager.Validate(ctx, ValidateRequest{KeyID: "node-a", CertPEM: cert1}); err != nil {
		t.Fatalf("old cert should be valid during overlap: %v", err)
	}

	clock.Advance(3 * time.Minute)
	if _, err := manager.Validate(ctx, ValidateRequest{KeyID: "node-a", CertPEM: cert1}); !errors.Is(err, ErrLeaseMismatch) {
		t.Fatalf("expected old cert to expire: %v", err)
	}

	clock.Advance(20 * time.Minute)
	cert3 := generateCert(t, clock.Now().Add(-time.Second), clock.Now().Add(15*time.Minute))
	reissued, err := manager.Reissue(ctx, ReissueRequest{
		KeyID:   "node-a",
		CertPEM: cert3,
		BoundTo: "app-alpha",
	})
	if err != nil {
		t.Fatalf("reissue: %v", err)
	}
	if reissued.LeaseID == renewed.LeaseID {
		t.Fatalf("reissue should rotate lease id")
	}
	if _, err := manager.Validate(ctx, ValidateRequest{KeyID: "node-a", CertPEM: cert3}); err != nil {
		t.Fatalf("validate reissued cert: %v", err)
	}
}

func newTestClock(now time.Time) *testClock {
	return &testClock{now: now}
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func generateCert(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	if !notAfter.After(notBefore) {
		notAfter = notBefore.Add(time.Hour)
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serial.String()},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	var buf strings.Builder
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}
	return []byte(buf.String())
}

func bytesRepeat(b byte, count int) []byte {
	buf := make([]byte, count)
	for i := range buf {
		buf[i] = b
	}
	return buf
}
