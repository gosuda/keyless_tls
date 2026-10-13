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

// ErrStaleRevision means another writer committed a newer lease revision.
var ErrStaleRevision = errors.New("stale lease revision")

type Store interface {
	Save(ctx context.Context, state *leaseState) error
	Load(ctx context.Context, leaseID string) (*leaseState, error)
}

// LeaseRevision identifies the exact committed ciphertext for an identity.
// Epoch zero and the zero digest represent an identity not yet issued.
type LeaseRevision struct {
	Epoch  int
	Digest [sha256.Size]byte
}

// RevisionAuthority is the authoritative, durable lease head registry.
//
// Implementations must store revisions outside the lease directory's backup and
// write-access boundary. LoadRevision must be linearizable and return
// ErrLeaseNotFound for unissued identities. CommitRevision must atomically and
// durably replace expected with next, reject mismatches with ErrStaleRevision,
// and never permit a previously committed epoch to be reused or rolled back.
// All DiskStore instances sharing a lease must use the same authority.
type RevisionAuthority interface {
	LoadRevision(ctx context.Context, leaseID string) (LeaseRevision, error)
	CommitRevision(ctx context.Context, leaseID string, expected, next LeaseRevision) error
}

type DiskStore struct {
	dir       string
	aead      cipher.AEAD
	authority RevisionAuthority
}

func NewDiskStore(dir string, secret []byte, authority RevisionAuthority) (*DiskStore, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, fmt.Errorf("%w: keyless dir is required", ErrInvalidRequest)
	}
	if len(secret) != 32 {
		return nil, fmt.Errorf("%w: secret must be 32 bytes", ErrInvalidRequest)
	}
	if authority == nil {
		return nil, fmt.Errorf("%w: revision authority is required", ErrInvalidRequest)
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

	return &DiskStore{dir: dir, aead: aead, authority: authority}, nil
}

func (d *DiskStore) Save(ctx context.Context, state *leaseState) error {
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
	if state.Current.Epoch < 1 {
		return fmt.Errorf("%w: current epoch must be positive", ErrInvalidRequest)
	}

	expected, err := d.authority.LoadRevision(ctx, leaseID)
	if errors.Is(err, ErrLeaseNotFound) {
		expected = LeaseRevision{}
	} else if err != nil {
		return fmt.Errorf("load lease revision: %w", err)
	}
	if state.Current.Epoch != expected.Epoch+1 {
		return ErrStaleRevision
	}

	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal lease state: %w", err)
	}
	nonce := make([]byte, d.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate lease nonce: %w", err)
	}
	ciphertext := d.aead.Seal(nil, nonce, payload, nil)
	blob := append(nonce, ciphertext...)
	next := LeaseRevision{Epoch: state.Current.Epoch, Digest: sha256.Sum256(blob)}
	path := d.pathForRevision(leaseID, next)

	// Each candidate has a unique name. Failed CAS writers cannot overwrite
	// the committed blob, and an uncommitted candidate is never loaded.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create lease revision: %w", err)
	}
	if _, err := file.Write(blob); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write lease revision: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("sync lease revision: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close lease revision: %w", err)
	}
	if err := syncRevisionDirectory(d.dir); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("sync lease directory: %w", err)
	}

	// Publishing the authoritative head is the linearization point. On an
	// ambiguous authority failure the candidate must be retained: removing
	// it could remove a revision that actually committed.
	if err := d.authority.CommitRevision(ctx, leaseID, expected, next); err != nil {
		if errors.Is(err, ErrStaleRevision) {
			_ = os.Remove(path)
		}
		return fmt.Errorf("commit lease revision: %w", err)
	}
	return nil
}

// The authority must not commit a blob whose directory entry is uncommitted.
// Windows does not support synchronizing a directory through os.File.Sync;
// after a crash, missing state still fails closed.
func syncRevisionDirectory(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func (d *DiskStore) Load(ctx context.Context, leaseID string) (*leaseState, error) {
	leaseID = normalizeLeaseID(leaseID)
	if leaseID == "" {
		return nil, ErrInvalidLeaseID
	}
	revision, err := d.authority.LoadRevision(ctx, leaseID)
	if err != nil {
		return nil, err
	}
	if revision.Epoch < 1 || revision.Digest == ([sha256.Size]byte{}) {
		return nil, fmt.Errorf("%w: invalid committed lease revision", ErrCorruptStore)
	}

	path := d.pathForRevision(leaseID, revision)
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read committed lease revision: %v", ErrCorruptStore, err)
	}
	if sha256.Sum256(blob) != revision.Digest {
		return nil, d.markCorrupt(path, errors.New("committed lease digest mismatch"))
	}
	if len(blob) <= d.aead.NonceSize() {
		return nil, d.markCorrupt(path, errors.New("payload truncated"))
	}

	plaintext, err := d.aead.Open(nil, blob[:d.aead.NonceSize()], blob[d.aead.NonceSize():], nil)
	if err != nil {
		return nil, d.markCorrupt(path, err)
	}
	var state leaseState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, d.markCorrupt(path, err)
	}
	if normalizeLeaseID(state.LeaseID) != leaseID || normalizeLeaseID(state.Current.LeaseID) != leaseID {
		return nil, d.markCorrupt(path, errors.New("lease id mismatch"))
	}
	if state.Current.Epoch != revision.Epoch {
		return nil, d.markCorrupt(path, errors.New("lease epoch mismatch"))
	}
	return &state, nil
}

func (d *DiskStore) markCorrupt(path string, cause error) error {
	corruptPath := path + ".corrupt"
	_ = os.Remove(corruptPath)
	_ = os.Rename(path, corruptPath)
	return fmt.Errorf("%w: %v", ErrCorruptStore, cause)
}

func (d *DiskStore) pathForRevision(leaseID string, revision LeaseRevision) string {
	return fmt.Sprintf("%s.%d.%x", d.pathForLease(leaseID), revision.Epoch, revision.Digest)
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
