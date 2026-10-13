package lifecycle

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

// Test-only CAS model. In-memory authorities are not safe for production:
// a process restart discards the committed revision history.
type memoryRevisionAuthority struct {
	mu        sync.Mutex
	revisions map[string]LeaseRevision
}

func newMemoryRevisionAuthority() *memoryRevisionAuthority {
	return &memoryRevisionAuthority{revisions: make(map[string]LeaseRevision)}
}

func (a *memoryRevisionAuthority) LoadRevision(_ context.Context, leaseID string) (LeaseRevision, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	revision, ok := a.revisions[leaseID]
	if !ok {
		return LeaseRevision{}, ErrLeaseNotFound
	}
	return revision, nil
}

func (a *memoryRevisionAuthority) CommitRevision(_ context.Context, leaseID string, expected, next LeaseRevision) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.revisions[leaseID] != expected || next.Epoch != expected.Epoch+1 {
		return ErrStaleRevision
	}
	a.revisions[leaseID] = next
	return nil
}

func testRevisionState(leaseID string, epoch int) *leaseState {
	return &leaseState{
		LeaseID: leaseID,
		Current: IdentityBundle{
			LeaseID: leaseID,
			CertPEM: []byte("cert"),
			KeyPEM: []byte("key"),
			ChainPEM: []byte("chain"),
			Epoch: epoch,
			NotBefore: time.Now().Add(-time.Minute),
			NotAfter: time.Now().Add(time.Hour),
		},
		UpdatedAt: time.Now(),
	}
}

func TestDiskStoreRejectsRestoredCredential(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	authority := newMemoryRevisionAuthority()
	store, err := NewDiskStore(t.TempDir(), repeatBytes(0x39, 32), authority)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, testRevisionState("lease-rollback", 1)); err != nil {
		t.Fatal(err)
	}
	oldRevision, err := authority.LoadRevision(ctx, "lease-rollback")
	if err != nil {
		t.Fatal(err)
	}
	oldBlob, err := os.ReadFile(store.pathForRevision("lease-rollback", oldRevision))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, testRevisionState("lease-rollback", 2)); err != nil {
		t.Fatal(err)
	}
	newRevision, err := authority.LoadRevision(ctx, "lease-rollback")
	if err != nil {
		t.Fatal(err)
	}
	if newRevision == oldRevision || newRevision.Epoch != 2 {
		t.Fatalf("authority did not advance: %+v", newRevision)
	}

	// A previously authentic ciphertext cannot replace the committed head.
	if err := os.WriteFile(store.pathForRevision("lease-rollback", newRevision), oldBlob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx, "lease-rollback"); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("restored epoch 1 must not be accepted: %v", err)
	}
	committed, err := authority.LoadRevision(ctx, "lease-rollback")
	if err != nil || committed != newRevision {
		t.Fatalf("authority must not roll back: got=%+v err=%v", committed, err)
	}
}

func TestDiskStoreRejectsSnapshotWithoutCommittedBlob(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	authority := newMemoryRevisionAuthority()
	store, err := NewDiskStore(t.TempDir(), repeatBytes(0x49, 32), authority)
	if err != nil {
		t.Fatal(err)
	}
	for epoch := 1; epoch <= 2; epoch++ {
		if err := store.Save(ctx, testRevisionState("lease-snapshot", epoch)); err != nil {
			t.Fatal(err)
		}
	}
	revision, err := authority.LoadRevision(ctx, "lease-snapshot")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(store.pathForRevision("lease-snapshot", revision)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx, "lease-snapshot"); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("missing committed revision must fail closed: %v", err)
	}
}

func TestDiskStoreConcurrentWriters(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	authority := newMemoryRevisionAuthority()
	dir := t.TempDir()
	secret := repeatBytes(0x59, 32)
	first, err := NewDiskStore(dir, secret, authority)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewDiskStore(dir, secret, authority)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Save(ctx, testRevisionState("lease-race", 1)); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	for index, store := range []*DiskStore{first, second} {
		state := testRevisionState("lease-race", 2)
		state.Current.KeyPEM = []byte{byte(index)}
		go func() {
			<-start
			results <- store.Save(ctx, state)
		}()
	}
	close(start)
	var successes, stale int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrStaleRevision):
			stale++
		default:
			t.Fatalf("unexpected concurrent result: %v", err)
		}
	}
	if successes != 1 || stale != 1 {
		t.Fatalf("writes: successes=%d stale=%d", successes, stale)
	}
	state, err := second.Load(ctx, "lease-race")
	if err != nil || state.Current.Epoch != 2 {
		t.Fatalf("load committed winner: state=%+v err=%v", state, err)
	}
}

func TestDiskStoreRequiresIndependentAuthority(t *testing.T) {
	t.Parallel()
	if _, err := NewDiskStore(t.TempDir(), repeatBytes(0x69, 32), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected invalid request for missing authority, got %v", err)
	}
}

func TestDiskStoreRejectsSkippedInitialEpoch(t *testing.T) {
	t.Parallel()
	store, err := NewDiskStore(t.TempDir(), repeatBytes(0x79, 32), newMemoryRevisionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), testRevisionState("lease-new", 3)); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("skipped initial epoch must not commit: %v", err)
	}
}
