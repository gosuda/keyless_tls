package lifecycle

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLifecycleIssueLoadRenewAndValidate(t *testing.T) {
	t.Parallel()

	ctx := leaseTestContext("lease-a")
	clock := newTestClock(time.Now().UTC())
	manager := newTestManager(t, clock, true)

	issued, err := manager.IssueIdentity(ctx, "lease-a", testProof("lease-a", OperationIssue, "nonce-issue-a"), map[string]string{"node": "alpha"})
	if err != nil {
		t.Fatalf("issue identity: %v", err)
	}
	if issued.Epoch != 1 {
		t.Fatalf("expected epoch=1, got %d", issued.Epoch)
	}

	loaded, err := manager.LoadIdentity(ctx, "lease-a", testProof("lease-a", OperationLoad, "nonce-load-a"))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	if loaded.LeaseID != "lease-a" {
		t.Fatalf("load lease id mismatch: got %s", loaded.LeaseID)
	}

	issuedLeaf := mustParseLeaf(t, issued.CertPEM)
	result, err := manager.ValidateIdentity("lease-a", issuedLeaf)
	if err != nil {
		t.Fatalf("validate issued identity: %v", err)
	}
	if result.UsingPrior {
		t.Fatalf("issued identity should not be marked prior")
	}

	renewed, err := manager.RenewIdentity(ctx, "lease-a", testProof("lease-a", OperationRenew, "nonce-renew-a"))
	if err != nil {
		t.Fatalf("renew identity: %v", err)
	}
	if renewed.Epoch != 2 {
		t.Fatalf("expected epoch=2 after renew, got %d", renewed.Epoch)
	}
	renewedLeaf := mustParseLeaf(t, renewed.CertPEM)
	if _, err := manager.ValidateIdentity("lease-a", renewedLeaf); err != nil {
		t.Fatalf("validate renewed identity: %v", err)
	}

	priorResult, err := manager.ValidateIdentity("lease-a", issuedLeaf)
	if err != nil {
		t.Fatalf("validate prior during overlap: %v", err)
	}
	if !priorResult.UsingPrior {
		t.Fatalf("expected prior cert to be accepted during overlap")
	}

	clock.Advance(3 * time.Minute)
	if _, err := manager.ValidateIdentity("lease-a", issuedLeaf); !errors.Is(err, ErrOverlapExpired) {
		t.Fatalf("expected overlap expiry error, got %v", err)
	}
}

func TestLifecycleChallengeAndReissueRules(t *testing.T) {
	t.Parallel()

	ctx := leaseTestContext("lease-b")
	clock := newTestClock(time.Now().UTC())
	manager := newTestManager(t, clock, true)

	if _, err := manager.IssueIdentity(ctx, "lease-b", ChallengeProof{}, nil); !errors.Is(err, ErrChallengeRequired) {
		t.Fatalf("expected challenge required, got %v", err)
	}

	if _, err := manager.IssueIdentity(ctx, "lease-b", ChallengeProof{Nonce: "bad", Token: "proof"}, nil); !errors.Is(err, ErrChallengeRejected) {
		t.Fatalf("expected challenge rejected, got %v", err)
	}

	if _, err := manager.IssueIdentity(ctx, "lease-b", testProof("lease-b", OperationIssue, "nonce-issue-b"), nil); err != nil {
		t.Fatalf("issue identity: %v", err)
	}

	if _, err := manager.ReissueIdentity(ctx, "lease-b", testProof("lease-b", OperationReissue, "nonce-reissue-b"), "rotation"); err != nil {
		t.Fatalf("reissue identity: %v", err)
	}
	if _, err := manager.ReissueIdentity(ctx, "lease-b", testProof("lease-b", OperationReissue, "nonce-reissue-b-2"), "again"); !errors.Is(err, ErrReissueRateLimit) {
		t.Fatalf("expected reissue rate limit, got %v", err)
	}
}

func TestLifecycleLoadCorruptionIsDeterministic(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clock := newTestClock(time.Now().UTC())
	manager := newTestManager(t, clock, false)

	if _, err := manager.IssueIdentity(ctx, "lease-corrupt", ChallengeProof{}, nil); err != nil {
		t.Fatalf("issue identity: %v", err)
	}

	store := manager.cfg.Store.(*DiskStore)
	path := store.pathForLease("lease-corrupt")
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("overwrite store file: %v", err)
	}

	if _, err := manager.LoadIdentity(ctx, "lease-corrupt", ChallengeProof{}); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("expected corrupt store error, got %v", err)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatalf("expected corrupt marker file: %v", err)
	}
}

func TestLifecycleValidateRejectsMismatchedLease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clock := newTestClock(time.Now().UTC())
	manager := newTestManager(t, clock, false)

	if _, err := manager.IssueIdentity(ctx, "lease-match", ChallengeProof{}, nil); err != nil {
		t.Fatalf("issue identity: %v", err)
	}
	issuedOther, err := manager.IssueIdentity(ctx, "lease-other", ChallengeProof{}, nil)
	if err != nil {
		t.Fatalf("issue identity: %v", err)
	}

	cert := mustParseLeaf(t, issuedOther.CertPEM)
	if _, err := manager.ValidateIdentity("lease-match", cert); !errors.Is(err, ErrLeaseMismatch) {
		t.Fatalf("expected lease mismatch, got %v", err)
	}
}

type leaseTestPrincipalKey struct{}

type testLeaseAuthorizer struct {
	mu   sync.Mutex
	used map[string]struct{}
}

func (a *testLeaseAuthorizer) AuthorizeLease(ctx context.Context, leaseID string, operation LeaseOperation, proof ChallengeProof) error {
	principal, ok := ctx.Value(leaseTestPrincipalKey{}).(string)
	if !ok || principal != leaseID {
		return errors.New("principal is not authorized for lease")
	}
	if proof.Token != fmt.Sprintf("token:%s:%s", leaseID, operation) {
		return errors.New("proof is not bound to lease and operation")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.used[proof.Nonce]; ok {
		return errors.New("proof has already been used")
	}
	a.used[proof.Nonce] = struct{}{}
	return nil
}

func leaseTestContext(leaseID string) context.Context {
	return context.WithValue(context.Background(), leaseTestPrincipalKey{}, leaseID)
}

func testProof(leaseID string, operation LeaseOperation, nonce string) ChallengeProof {
	return ChallengeProof{Nonce: nonce, Token: fmt.Sprintf("token:%s:%s", leaseID, operation)}
}

func newTestManager(t *testing.T, clock *testClock, requireAuthorization bool) *Manager {
	t.Helper()

	cfg := newTestManagerConfig(t, clock)
	var (
		manager *Manager
		err     error
	)
	if requireAuthorization {
		cfg.Authorizer = &testLeaseAuthorizer{used: make(map[string]struct{})}
		manager, err = NewManager(cfg)
	} else {
		manager, err = NewTrustedManager(cfg)
	}
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return manager
}

func newTestManagerConfig(t *testing.T, clock *testClock) ManagerConfig {
	t.Helper()

	issuerCertPEM, issuerKeyPEM := issueTestCA(t, clock.Now().Add(-time.Hour), clock.Now().Add(365*24*time.Hour))
	store, err := NewDiskStore(t.TempDir(), bytesRepeat(0x41, 32))
	if err != nil {
		t.Fatalf("create disk store: %v", err)
	}
	return ManagerConfig{
		Store:            store,
		IssuerCertPEM:    issuerCertPEM,
		IssuerKeyPEM:     issuerKeyPEM,
		CertTTL:          30 * time.Minute,
		OverlapGrace:     2 * time.Minute,
		ReissueMinPeriod: 10 * time.Second,
		Now:              clock.Now,
	}
}

func issueTestCA(t *testing.T, notBefore, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "test-issuer",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create issuer cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM
}

func mustParseLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	cert, err := parseLeafCertPEM(certPEM)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return cert
}

func bytesRepeat(v byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = v
	}
	return out
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock(now time.Time) *testClock {
	return &testClock{now: now}
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
