package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func testLeaseState(id string, epoch int) *leaseState {
	return &leaseState{
		LeaseID: id,
		Current: IdentityBundle{
			LeaseID: id,
			Epoch:   epoch,
		},
	}
}

func TestDiskStoreDoesNotFollowPredictableTemporarySymlink(t *testing.T) {
	t.Parallel()

	store, err := NewDiskStore(t.TempDir(), repeatBytes(0x51, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	victim := filepath.Join(t.TempDir(), "victim")
	const original = "must not be truncated"
	if err := os.WriteFile(victim, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	legacyTemp := store.pathForLease("lease-symlink") + ".tmp"
	if err := os.Symlink(victim, legacyTemp); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if err := store.Save(context.Background(), testLeaseState("lease-symlink", 1)); err != nil {
		t.Fatalf("safe save: %v", err)
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("victim changed from %q to %q", original, got)
	}
	loaded, err := store.Load(context.Background(), "lease-symlink")
	if err != nil || loaded.Current.Epoch != 1 {
		t.Fatalf("load after safe save: %v, state=%+v", err, loaded)
	}
}

func TestDiskStoreRejectsSymlinkedDirectory(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	actual := filepath.Join(parent, "actual")
	if err := os.Mkdir(actual, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(actual, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if store, err := NewDiskStore(alias, repeatBytes(0x52, 32)); err == nil {
		_ = store.Close()
		t.Fatal("accepted symlinked store directory")
	}
	if store, err := NewDiskStore(filepath.Join(alias, "child"), repeatBytes(0x52, 32)); err == nil {
		_ = store.Close()
		t.Fatal("accepted symlinked path component")
	}
}

func TestDiskStoreRepairsOwnedDirectoryPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not describe Windows ACLs")
	}
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	store, err := NewDiskStore(dir, repeatBytes(0x53, 32))
	if err != nil {
		t.Fatalf("secure owned directory: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("directory permissions = %04o, want 0700", info.Mode().Perm())
	}
}

func TestDiskStoreRejectsOtherUsersDirectory(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires root on Linux to create a directory owned by another user")
	}
	dir := filepath.Join(t.TempDir(), "foreign")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 1, 1); err != nil {
		t.Skipf("chown unavailable: %v", err)
	}
	if store, err := NewDiskStore(dir, repeatBytes(0x54, 32)); err == nil {
		_ = store.Close()
		t.Fatal("accepted directory owned by another user")
	}
}

func TestDiskStoreUsesPinnedDirectoryAfterRename(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" || runtime.GOOS == "js" {
		t.Skip("the operating system does not pin directory handles across renames")
	}
	t.Parallel()

	parent := t.TempDir()
	original := filepath.Join(parent, "store")
	store, err := NewDiskStore(original, repeatBytes(0x55, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	moved := filepath.Join(parent, "moved")
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(parent, "decoy")
	if err := os.Mkdir(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, original); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := store.Save(context.Background(), testLeaseState("lease-pinned", 7)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(moved, leaseFileName("lease-pinned"))); err != nil {
		t.Fatalf("write did not use the pinned directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(decoy, leaseFileName("lease-pinned"))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("write followed a replacement directory entry: %v", err)
	}
	loaded, err := store.Load(context.Background(), "lease-pinned")
	if err != nil || loaded.Current.Epoch != 7 {
		t.Fatalf("load from pinned directory: err=%v state=%+v", err, loaded)
	}
}

func TestDiskStoreConcurrentSavesAreAtomic(t *testing.T) {
	t.Parallel()

	const id = "lease-concurrent"
	store, err := NewDiskStore(t.TempDir(), repeatBytes(0x56, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Save(context.Background(), testLeaseState(id, 1)); err != nil {
		t.Fatal(err)
	}

	const writers = 16
	const readers = 4
	var group sync.WaitGroup
	errs := make(chan error, writers+readers)
	start := make(chan struct{})
	for i := range writers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			if err := store.Save(context.Background(), testLeaseState(id, i+2)); err != nil {
				errs <- fmt.Errorf("save %d: %w", i, err)
			}
		}()
	}
	for range readers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			for range 20 {
				loaded, err := store.Load(context.Background(), id)
				if err != nil {
					errs <- err
					return
				}
				if loaded.LeaseID != id || loaded.Current.LeaseID != id {
					errs <- fmt.Errorf("observed torn state: %+v", loaded)
					return
				}
			}
		}()
	}
	close(start)
	group.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
