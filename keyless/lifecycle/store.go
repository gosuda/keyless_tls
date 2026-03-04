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
	"strings"
)

type Store interface {
	Save(ctx context.Context, state *leaseState) error
	Load(ctx context.Context, leaseID string) (*leaseState, error)
}

type DiskStore struct {
	dir  string
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

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create keyless dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("lock keyless dir perms: %w", err)
	}

	return &DiskStore{
		dir:  dir,
		aead: aead,
	}, nil
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

	path := d.pathForLease(leaseID)
	temp := path + ".tmp"
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

	file, err := os.OpenFile(temp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(blob); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return nil
}

func (d *DiskStore) Load(_ context.Context, leaseID string) (*leaseState, error) {
	leaseID = normalizeLeaseID(leaseID)
	if leaseID == "" {
		return nil, ErrInvalidLeaseID
	}
	path := d.pathForLease(leaseID)
	blob, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrLeaseNotFound
		}
		return nil, err
	}
	nonceSize := d.aead.NonceSize()
	if len(blob) <= nonceSize {
		return nil, d.markCorrupt(path, errors.New("payload truncated"))
	}

	nonce := blob[:nonceSize]
	ciphertext := blob[nonceSize:]
	plaintext, err := d.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, d.markCorrupt(path, err)
	}

	var state leaseState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, d.markCorrupt(path, err)
	}
	if normalizeLeaseID(state.LeaseID) != leaseID {
		return nil, d.markCorrupt(path, errors.New("lease id mismatch"))
	}
	if normalizeLeaseID(state.Current.LeaseID) != leaseID {
		return nil, d.markCorrupt(path, errors.New("current lease id mismatch"))
	}
	return &state, nil
}

func (d *DiskStore) markCorrupt(path string, cause error) error {
	corruptPath := path + ".corrupt"
	_ = os.Remove(corruptPath)
	_ = os.Rename(path, corruptPath)
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
