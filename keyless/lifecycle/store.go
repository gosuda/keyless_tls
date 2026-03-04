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
	Load(ctx context.Context, keyID string) (*leaseState, error)
}

type DiskStore struct {
	dir  string
	aead cipher.AEAD
}

func NewDiskStore(dir string, secret []byte) (*DiskStore, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, fmt.Errorf("%w: directory is required", ErrInvalidRequest)
	}
	if len(secret) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}
	aead, err := newAEAD(secret)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create keyless dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("lock keyless dir: %w", err)
	}
	return &DiskStore{dir: dir, aead: aead}, nil
}

func (d *DiskStore) Save(ctx context.Context, state *leaseState) error {
	if state == nil {
		return fmt.Errorf("%w: state is required", ErrInvalidRequest)
	}
	path := d.pathForKey(state.KeyID)
	temp := path + ".tmp"
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal lease: %w", err)
	}
	nonce := make([]byte, d.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := d.aead.Seal(nil, nonce, payload, nil)
	data := append(nonce, ciphertext...)
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

func (d *DiskStore) Load(ctx context.Context, keyID string) (*leaseState, error) {
	path := d.pathForKey(keyID)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrLeaseNotFound
		}
		return nil, err
	}
	nonceSize := d.aead.NonceSize()
	if len(data) <= nonceSize {
		return nil, d.markCorrupt(path, fmt.Errorf("payload truncated"))
	}
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]
	plaintext, err := d.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, d.markCorrupt(path, err)
	}
	var state leaseState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, d.markCorrupt(path, err)
	}
	return &state, nil
}

func (d *DiskStore) pathForKey(keyID string) string {
	id := sanitizeKey(keyID)
	hash := sha256.Sum256([]byte(keyID))
	file := fmt.Sprintf("%s-%x.lease", id, hash[:4])
	return filepath.Join(d.dir, file)
}

func (d *DiskStore) markCorrupt(path string, cause error) error {
	corrupt := path + ".corrupt"
	_ = os.Remove(corrupt)
	_ = os.Rename(path, corrupt)
	return fmt.Errorf("%w: %v", ErrLeaseCorrupted, cause)
}

func sanitizeKey(keyID string) string {
	if strings.TrimSpace(keyID) == "" {
		return "anonymous"
	}
	var b strings.Builder
	for _, r := range keyID {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "anonymous"
	}
	return b.String()
}

func newAEAD(secret []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
