package lifecycle

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

	root, err := openPrivateStoreDirectory(dir)
	if err != nil {
		return nil, fmt.Errorf("open keyless dir: %w", err)
	}

	return &DiskStore{
		dir:  dir,
		root: root,
		aead: aead,
	}, nil
}

// Close releases the pinned directory handle. Do not use the store after Close.
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

	name := leaseFileName(leaseID)
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

	var suffix [16]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("generate temporary filename: %w", err)
	}
	tempName := ".lease-" + hex.EncodeToString(suffix[:]) + ".tmp"
	file, err := d.root.OpenFile(tempName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary lease: %w", err)
	}
	defer d.root.Remove(tempName)

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("stat temporary lease: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return fmt.Errorf("temporary lease is not a regular file")
	}
	if err := validateStoreOwner(info); err != nil {
		_ = file.Close()
		return fmt.Errorf("temporary lease owner: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("set temporary lease permissions: %w", err)
	}
	if _, err := file.Write(blob); err != nil {
		_ = file.Close()
		return fmt.Errorf("write temporary lease: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync temporary lease: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary lease: %w", err)
	}
	if err := d.root.Rename(tempName, name); err != nil {
		return fmt.Errorf("install lease: %w", err)
	}

	// Persist the rename, not only the file contents. Windows does not support
	// syncing directory handles through os.File.Sync.
	if runtime.GOOS != "windows" {
		directory, err := d.root.Open(".")
		if err != nil {
			return fmt.Errorf("open keyless dir for sync: %w", err)
		}
		if err := directory.Sync(); err != nil {
			_ = directory.Close()
			return fmt.Errorf("sync keyless dir: %w", err)
		}
		if err := directory.Close(); err != nil {
			return fmt.Errorf("close keyless dir after sync: %w", err)
		}
	}
	return nil
}

func (d *DiskStore) Load(_ context.Context, leaseID string) (*leaseState, error) {
	leaseID = normalizeLeaseID(leaseID)
	if leaseID == "" {
		return nil, ErrInvalidLeaseID
	}
	name := leaseFileName(leaseID)
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
	return filepath.Join(d.dir, leaseFileName(leaseID))
}

func leaseFileName(leaseID string) string {
	base := sanitizePathToken(leaseID)
	hash := sha256.Sum256([]byte(leaseID))
	return fmt.Sprintf("%s-%x.lease", base, hash[:4])
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
