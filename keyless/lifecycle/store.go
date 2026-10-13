package lifecycle

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type Store interface {
	Save(ctx context.Context, state *leaseState) error
	Load(ctx context.Context, leaseID string) (*leaseState, error)
}

type DiskStore struct {
	dir  string
	root *os.Root
	aead cipher.AEAD
}

func NewDiskStore(dir string, secret []byte) (*DiskStore, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, fmt.Errorf("%w: keyless dir is required", ErrInvalidRequest)
	}
	if len(secret) != 32 {
		return nil, fmt.Errorf("%w: secret must be 32 bytes", ErrInvalidRequest)
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, fmt.Errorf("create block cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve keyless dir: %w", err)
	}
	root, err := openTrustedStoreRoot(absDir)
	if err != nil {
		return nil, fmt.Errorf("secure keyless dir: %w", err)
	}

	return &DiskStore{
		dir:  absDir,
		root: root,
		aead: aead,
	}, nil
}

// Close releases the pinned store directory. The store must not be used after Close.
func (d *DiskStore) Close() error {
	return d.root.Close()
}

func (d *DiskStore) Save(_ context.Context, state *leaseState) error {
	if state == nil {
		return fmt.Errorf("%w: state is required", ErrInvalidRequest)
	}
	leaseID := normalizeLeaseID(state.LeaseID)
	if leaseID == "" {
		return ErrInvalidLeaseID
	}
	if normalizeLeaseID(state.Current.LeaseID) != leaseID {
		return fmt.Errorf("%w: current lease id mismatch", ErrInvalidRequest)
	}

	name := filepath.Base(d.pathForLease(leaseID))
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	nonce := make([]byte, d.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := d.aead.Seal(nil, nonce, payload, nil)
	blob := append(nonce, ciphertext...)

	// Exclusive creation prevents existing symlinks, while a random name
	// permits concurrent saves without sharing a temporary pathname.
	temp, file, err := d.createTemp()
	if err != nil {
		return fmt.Errorf("create temporary lease file: %w", err)
	}
	defer func() { _ = d.root.Remove(temp) }()

	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("set temporary lease permissions: %w", err)
	}
	if _, err := file.Write(blob); err != nil {
		_ = file.Close()
		return fmt.Errorf("write temporary lease file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync temporary lease file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary lease file: %w", err)
	}
	if err := d.root.Rename(temp, name); err != nil {
		return fmt.Errorf("replace lease file: %w", err)
	}
	return d.syncDirectory()
}

// createTemp uses a cryptographically random filename and O_EXCL: neither a
// preexisting symlink nor a competing save can redirect its initial write.
func (d *DiskStore) createTemp() (string, *os.File, error) {
	for range 10 {
		var suffix [16]byte
		if _, err := io.ReadFull(rand.Reader, suffix[:]); err != nil {
			return "", nil, err
		}
		name := fmt.Sprintf(".lease-%x.tmp", suffix)
		file, err := d.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return name, file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, err
		}
	}
	return "", nil, errors.New("unable to allocate unique temporary lease filename")
}

func (d *DiskStore) syncDirectory() error {
	// Directory handle syncing is not supported consistently on Windows.
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := d.root.Open(".")
	if err != nil {
		return fmt.Errorf("open store directory for sync: %w", err)
	}
	err = dir.Sync()
	if closeErr := dir.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("sync store directory: %w", err)
	}
	return nil
}

func (d *DiskStore) Load(_ context.Context, leaseID string) (*leaseState, error) {
	leaseID = normalizeLeaseID(leaseID)
	if leaseID == "" {
		return nil, ErrInvalidLeaseID
	}
	name := filepath.Base(d.pathForLease(leaseID))
	info, err := d.root.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrLeaseNotFound
		}
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: lease is not a regular file", ErrCorruptStore)
	}
	blob, err := d.root.ReadFile(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrLeaseNotFound
		}
		return nil, err
	}
	nonceSize := d.aead.NonceSize()
	if len(blob) <= nonceSize {
		return nil, d.markCorrupt(name, errors.New("payload truncated"))
	}

	nonce := blob[:nonceSize]
	ciphertext := blob[nonceSize:]
	plaintext, err := d.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, d.markCorrupt(name, err)
	}

	var state leaseState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, d.markCorrupt(name, err)
	}
	if normalizeLeaseID(state.LeaseID) != leaseID {
		return nil, d.markCorrupt(name, errors.New("lease id mismatch"))
	}
	if normalizeLeaseID(state.Current.LeaseID) != leaseID {
		return nil, d.markCorrupt(name, errors.New("current lease id mismatch"))
	}
	return &state, nil
}

func (d *DiskStore) markCorrupt(name string, cause error) error {
	corruptName := name + ".corrupt"
	_ = d.root.Remove(corruptName)
	_ = d.root.Rename(name, corruptName)
	return fmt.Errorf("%w: %v", ErrCorruptStore, cause)
}

func (d *DiskStore) pathForLease(leaseID string) string {
	base := sanitizePathToken(leaseID)
	hash := sha256.Sum256([]byte(leaseID))
	return filepath.Join(d.dir, fmt.Sprintf("%s-%x.lease", base, hash[:4]))
}

func sanitizePathToken(value string) string {
	if value == "" {
		return "anonymous"
	}
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('_')
	}
	if b.Len() == 0 {
		return "anonymous"
	}
	return b.String()
}

// openTrustedStoreRoot walks directory components through pinned os.Root handles.
// It never follows symlinks or changes permissions on directories of unknown ownership.
func openTrustedStoreRoot(absDir string) (*os.Root, error) {
	volume := filepath.VolumeName(absDir)
	base := volume + string(filepath.Separator)
	if absDir == base {
		return nil, errors.New("store path must not be a volume root")
	}

	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	keepOpen := false
	defer func() {
		if !keepOpen {
			_ = root.Close()
		}
	}()

	info, err := root.Stat(".")
	if err != nil {
		return nil, err
	}
	if err := validateStoreDirectory(info, false); err != nil {
		return nil, fmt.Errorf("untrusted ancestor %q: %w", base, err)
	}

	parts := strings.Split(strings.TrimPrefix(absDir, base), string(filepath.Separator))
	for i, part := range parts {
		info, err := root.Lstat(part)
		if errors.Is(err, os.ErrNotExist) {
			if err = root.Mkdir(part, 0o700); err != nil {
				return nil, fmt.Errorf("create store directory component %q: %w", part, err)
			}
			info, err = root.Lstat(part)
		}
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("store component %q is a symlink or not a directory", part)
		}

		next, openErr := root.OpenRoot(part)
		if openErr != nil {
			return nil, openErr
		}
		actual, statErr := next.Stat(".")
		if statErr != nil {
			_ = next.Close()
			return nil, statErr
		}
		if !os.SameFile(info, actual) {
			_ = next.Close()
			return nil, fmt.Errorf("store component %q changed during validation", part)
		}
		if checkErr := validateStoreDirectory(actual, i == len(parts)-1); checkErr != nil {
			_ = next.Close()
			return nil, fmt.Errorf("untrusted store component %q: %w", part, checkErr)
		}
		_ = root.Close()
		root = next
	}

	// Chmod is relative to the verified root itself, not an untrusted pathname.
	if err := root.Chmod(".", 0o700); err != nil {
		return nil, fmt.Errorf("set store directory permissions: %w", err)
	}
	keepOpen = true
	return root, nil
}
