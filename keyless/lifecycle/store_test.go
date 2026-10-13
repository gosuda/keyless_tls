package lifecycle

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestDiskStoreSaveLoadAndPerms(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := NewDiskStore(dir, t.TempDir(), repeatBytes(0x19, 32))
	if err != nil {
		t.Fatalf("new disk store: %v", err)
	}

	state := &leaseState{
		LeaseID: "lease-store",
		Current: IdentityBundle{
			LeaseID:   "lease-store",
			CertPEM:   []byte("cert"),
			KeyPEM:    []byte("key"),
			ChainPEM:  []byte("chain"),
			Epoch:     1,
			NotBefore: time.Now().Add(-time.Minute),
			NotAfter:  time.Now().Add(time.Hour),
		},
		UpdatedAt: time.Now(),
	}
	if err := store.Save(context.Background(), state); err != nil {
		t.Fatalf("save state: %v", err)
	}

	path := store.pathForLease("lease-store")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("state file perms=%v want=0600", info.Mode().Perm())
	}

	loaded, err := store.Load(context.Background(), "lease-store")
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if loaded.LeaseID != "lease-store" {
		t.Fatalf("lease mismatch: got=%q", loaded.LeaseID)
	}
	if loaded.Current.Epoch != 1 {
		t.Fatalf("epoch mismatch: got=%d", loaded.Current.Epoch)
	}
}

func TestDiskStoreCorruptionMarking(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := NewDiskStore(dir, t.TempDir(), repeatBytes(0x29, 32))
	if err != nil {
		t.Fatalf("new disk store: %v", err)
	}

	state := &leaseState{
		LeaseID: "lease-corrupt",
		Current: IdentityBundle{
			LeaseID:   "lease-corrupt",
			CertPEM:   []byte("cert"),
			KeyPEM:    []byte("key"),
			ChainPEM:  []byte("chain"),
			Epoch:     1,
			NotBefore: time.Now().Add(-time.Minute),
			NotAfter:  time.Now().Add(time.Hour),
		},
		UpdatedAt: time.Now(),
	}
	if err := store.Save(context.Background(), state); err != nil {
		t.Fatalf("save state: %v", err)
	}

	path := store.pathForLease("lease-corrupt")
	if err := os.WriteFile(path, []byte("broken"), 0o600); err != nil {
		t.Fatalf("overwrite file: %v", err)
	}

	if _, err := store.Load(context.Background(), "lease-corrupt"); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("expected corrupt error, got %v", err)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatalf("expected corrupt marker file: %v", err)
	}
}

func TestDiskStoreRequiresValidInputs(t *testing.T) {
	t.Parallel()

	if _, err := NewDiskStore("", t.TempDir(), repeatBytes(0x30, 32)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected invalid request for empty dir, got %v", err)
	}
	if _, err := NewDiskStore(t.TempDir(), t.TempDir(), []byte("short")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected invalid request for short key, got %v", err)
	}
}

func repeatBytes(v byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = v
	}
	return out
}


func testLeaseState(leaseID string, epoch int) *leaseState {
	return &leaseState{
		LeaseID: leaseID,
		Current: IdentityBundle{
			LeaseID: leaseID,
			Epoch:   epoch,
			CertPEM: []byte("certificate"),
			NotAfter: time.Now().Add(time.Hour),
		},
		UpdatedAt: time.Now(),
	}
}

func TestDiskStoreRejectsReplayedBlob(t *testing.T) {
	t.Parallel()

	store, err := NewDiskStore(t.TempDir(), t.TempDir(), repeatBytes(0x42, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	state := testLeaseState("lease-replay", 1)
	if err := store.Save(ctx, state); err != nil {
		t.Fatal(err)
	}
	path := store.pathForLease(state.LeaseID)
	oldBlob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	state.Current.Epoch++
	if err := store.Save(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, oldBlob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx, state.LeaseID); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("replayed blob accepted: %v", err)
	}
}

func TestDiskStoreRejectsConcurrentStaleWriters(t *testing.T) {
	t.Parallel()

	dataDir, authorityDir := t.TempDir(), t.TempDir()
	key := repeatBytes(0x43, 32)
	first, err := NewDiskStore(dataDir, authorityDir, key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewDiskStore(dataDir, authorityDir, key)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := first.Save(ctx, testLeaseState("lease-cas", 1)); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, store := range []*DiskStore{first, second} {
		wg.Add(1)
		go func(store *DiskStore) {
			defer wg.Done()
			<-start
			results <- store.Save(ctx, testLeaseState("lease-cas", 2))
		}(store)
	}
	close(start)
	wg.Wait()
	close(results)
	var success, stale int
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrStaleEpoch):
			stale++
		default:
			t.Fatalf("unexpected save error: %v", err)
		}
	}
	if success != 1 || stale != 1 {
		t.Fatalf("expected one commit and one stale writer, got %d commits, %d stale", success, stale)
	}
}

func TestDiskStoreRecoversCommittedPendingWrite(t *testing.T) {
	t.Parallel()

	store, err := NewDiskStore(t.TempDir(), t.TempDir(), repeatBytes(0x44, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.Save(ctx, testLeaseState("lease-recover", 1)); err != nil {
		t.Fatal(err)
	}
	next := testLeaseState("lease-recover", 2)
	payload, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, store.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	blob := append(nonce, store.aead.Seal(nil, nonce, payload, nil)...)
	pending := store.pathForLease(next.LeaseID) + ".pending"
	if err := os.WriteFile(pending, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.writeCheckpoint(next.LeaseID, leaseCheckpoint{
		LeaseID: next.LeaseID,
		Epoch: next.Current.Epoch,
		Digest: sha256.Sum256(blob),
	}); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(ctx, next.LeaseID)
	if err != nil {
		t.Fatalf("recover committed staged blob: %v", err)
	}
	if loaded.Current.Epoch != 2 {
		t.Fatalf("recovered epoch: got %d, want 2", loaded.Current.Epoch)
	}
	if _, err := os.Stat(pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending write was not finalized: %v", err)
	}
}

func TestDiskStoreRejectsUnanchoredState(t *testing.T) {
	t.Parallel()

	store, err := NewDiskStore(t.TempDir(), t.TempDir(), repeatBytes(0x45, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.Save(ctx, testLeaseState("lease-unanchored", 1)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(store.pathForCheckpoint("lease-unanchored")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx, "lease-unanchored"); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("state without checkpoint accepted: %v", err)
	}
}

func TestDiskStoreAuthorityMustBeIndependent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	key := repeatBytes(0x46, 32)
	for _, authorityDir := range []string{dir, filepath.Join(dir, "nested")} {
		if _, err := NewDiskStore(dir, authorityDir, key); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("authority directory %q accepted: %v", authorityDir, err)
		}
	}
}
