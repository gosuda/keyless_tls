package lifecycle

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestDiskStoreSaveLoadAndPerms(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := NewDiskStore(dir, bytesRepeat(0x19, 32))
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
	if info.Mode().Perm() != 0o600 {
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
	store, err := NewDiskStore(dir, bytesRepeat(0x29, 32))
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
			Epoch:     3,
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

	if _, err := NewDiskStore("", bytesRepeat(0x30, 32)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected invalid request for empty dir, got %v", err)
	}
	if _, err := NewDiskStore(t.TempDir(), []byte("short")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected invalid request for short key, got %v", err)
	}
}
