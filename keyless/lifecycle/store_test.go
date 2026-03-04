package lifecycle

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestDiskStorePersistence(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDiskStore(dir, bytesRepeat(0x11, 32))
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	state := &leaseState{
		LeaseID:         "persist",
		KeyID:           "node-x",
		BoundTo:         "service",
		CertPEM:         []byte("cert"),
		CertFingerprint: "fp",
		IssuedAt:        time.Now(),
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(time.Hour),
		OverlapGrace:    5 * time.Minute,
	}
	if err := store.Save(context.Background(), state); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(store.pathForKey("node-x"))
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected perms: %o", info.Mode().Perm())
	}
	loaded, err := store.Load(context.Background(), "node-x")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.LeaseID != state.LeaseID {
		t.Fatalf("lease id: got %s", loaded.LeaseID)
	}
}

func TestDiskStoreCorruption(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDiskStore(dir, bytesRepeat(0x22, 32))
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	state := &leaseState{
		LeaseID:         "corrupt",
		KeyID:           "node-y",
		BoundTo:         "service",
		CertPEM:         []byte("cert"),
		CertFingerprint: "fp",
		IssuedAt:        time.Now(),
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(time.Hour),
		OverlapGrace:    5 * time.Minute,
	}
	if err := store.Save(context.Background(), state); err != nil {
		t.Fatalf("save: %v", err)
	}
	path := store.pathForKey("node-y")
	if err := os.WriteFile(path, []byte("bad"), 0o600); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	if _, err := store.Load(context.Background(), "node-y"); !errors.Is(err, ErrLeaseCorrupted) {
		t.Fatalf("expected corruption: %v", err)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatalf("corrupt marker missing: %v", err)
	}
}
