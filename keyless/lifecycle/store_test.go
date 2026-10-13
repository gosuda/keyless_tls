package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDiskStoreSaveLoadAndPerms(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := NewDiskStore(dir, repeatBytes(0x19, 32))
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
	store, err := NewDiskStore(dir, repeatBytes(0x29, 32))
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

	if _, err := NewDiskStore("", repeatBytes(0x30, 32)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected invalid request for empty dir, got %v", err)
	}
	if _, err := NewDiskStore(t.TempDir(), []byte("short")); !errors.Is(err, ErrInvalidRequest) {
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

func TestDiskStoreSymlinkDoesNotClobberTarget(t *testing.T) {
	t.Parallel()

	store, err := NewDiskStore(filepath.Join(t.TempDir(), "store"), repeatBytes(0x31, 32))
	if err != nil {
		t.Fatalf("new disk store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	victim := filepath.Join(t.TempDir(), "victim.txt")
	const original = "retain this data"
	if err := os.WriteFile(victim, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	name := store.pathForLease("symlink-lease")
	for _, candidate := range []string{name + ".tmp", name} {
		if err := os.Symlink(victim, candidate); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlinks unavailable: %v", err)
			}
			t.Fatalf("create symlink: %v", err)
		}
	}
	if err := store.Save(context.Background(), diskStoreTestState("symlink-lease", 1)); err != nil {
		t.Fatalf("save should not follow the precreated symlinks: %v", err)
	}
	contents, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != original {
		t.Fatalf("symlink target modified: %q", contents)
	}
	if loaded, err := store.Load(context.Background(), "symlink-lease"); err != nil || loaded.Current.Epoch != 1 {
		t.Fatalf("load saved lease: state=%+v err=%v", loaded, err)
	}
}

func TestDiskStoreRejectsSymlinkedDirectories(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	trusted := filepath.Join(parent, "trusted")
	if err := os.Mkdir(trusted, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(trusted, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatal(err)
	}
	for _, path := range []string{link, filepath.Join(link, "nested")} {
		if store, err := NewDiskStore(path, repeatBytes(0x32, 32)); err == nil {
			_ = store.Close()
			t.Fatalf("accepted symlinked directory %q", path)
		}
	}
	if _, err := os.Stat(filepath.Join(trusted, "nested")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created directory via a symlink: %v", err)
	}
}

func TestDiskStoreRejectsUntrustedDirectoryPermissions(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission semantics required")
	}

	dir := filepath.Join(t.TempDir(), "writable")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if store, err := NewDiskStore(dir, repeatBytes(0x33, 32)); err == nil {
		_ = store.Close()
		t.Fatal("accepted a group/world-writable store directory")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o777 {
		t.Fatalf("changed untrusted directory permissions: %v", info.Mode())
	}
}

func TestDiskStoreRejectsOtherUserOwnedDirectory(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires root on Linux for safe ownership test")
	}
	dir := filepath.Join(t.TempDir(), "foreign")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Skipf("chown unavailable: %v", err)
	}
	if store, err := NewDiskStore(dir, repeatBytes(0x34, 32)); err == nil {
		_ = store.Close()
		t.Fatal("accepted a directory owned by another user")
	}
}

func TestDiskStoreDirectoryPinnedAgainstPathReplacement(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Windows prevents renaming open directory handles")
	}
	base := t.TempDir()
	storeDir := filepath.Join(base, "store")
	store, err := NewDiskStore(storeDir, repeatBytes(0x35, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	moved := filepath.Join(base, "moved")
	if err := os.Rename(storeDir, moved); err != nil {
		t.Fatal(err)
	}
	attacker := filepath.Join(base, "attacker")
	if err := os.Mkdir(attacker, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(attacker, storeDir); err != nil {
		t.Fatal(err)
	}

	if err := store.Save(context.Background(), diskStoreTestState("pinned-lease", 1)); err != nil {
		t.Fatalf("save through pinned directory: %v", err)
	}
	name := filepath.Base(store.pathForLease("pinned-lease"))
	if _, err := os.Stat(filepath.Join(moved, name)); err != nil {
		t.Fatalf("file absent from pinned directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(attacker, name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("store followed replacement symlink: %v", err)
	}
}

func TestDiskStoreConcurrentAtomicSaves(t *testing.T) {
	t.Parallel()
	store, err := NewDiskStore(filepath.Join(t.TempDir(), "store"), repeatBytes(0x36, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	const writers = 16
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := range writers {
		wg.Add(1)
		go func(epoch int) {
			defer wg.Done()
			errs <- store.Save(context.Background(), diskStoreTestState("concurrent-lease", epoch))
		}(i + 1)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent save: %v", err)
		}
	}
	loaded, err := store.Load(context.Background(), "concurrent-lease")
	if err != nil {
		t.Fatalf("load after concurrent saves: %v", err)
	}
	if loaded.Current.Epoch < 1 || loaded.Current.Epoch > writers {
		t.Fatalf("invalid epoch %d", loaded.Current.Epoch)
	}

	entries, err := os.ReadDir(store.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".lease-") && strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("temporary file leaked: %s", entry.Name())
		}
	}
}

func diskStoreTestState(id string, epoch int) *leaseState {
	now := time.Now()
	return &leaseState{
		LeaseID: id,
		Current: IdentityBundle{
			LeaseID:   id,
			Epoch:     epoch,
			NotBefore: now.Add(-time.Minute),
			NotAfter:  now.Add(time.Hour),
		},
		UpdatedAt: now,
	}
}
