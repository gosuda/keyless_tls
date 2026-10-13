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

// ErrStaleEpoch indicates that another writer committed a newer lease state.
var ErrStaleEpoch = errors.New("lease epoch is stale")

type Store interface {
	Save(ctx context.Context, state *leaseState) error
	Load(ctx context.Context, leaseID string) (*leaseState, error)
}

type DiskStore struct {
	dir          string
	authorityDir string
	aead         cipher.AEAD
}

type leaseCheckpoint struct {
	LeaseID string              `json:"lease_id"`
	Epoch   int                 `json:"epoch"`
	Digest  [sha256.Size]byte    `json:"digest"`
}

// NewDiskStore requires an independently authoritative checkpoint directory.
// An actor able to replace lease files must not be able to replace or roll back
// checkpoints. In particular, authorityDir must not be included in snapshots
// or backups used to restore dir.
func NewDiskStore(dir, authorityDir string, secret []byte) (*DiskStore, error) {
	dir = strings.TrimSpace(dir)
	authorityDir = strings.TrimSpace(authorityDir)
	if dir == "" || authorityDir == "" {
		return nil, fmt.Errorf("%w: lease and authority dirs are required", ErrInvalidRequest)
	}
	if len(secret) != 32 {
		return nil, fmt.Errorf("%w: secret must be 32 bytes", ErrInvalidRequest)
	}

	for _, path := range []string{dir, authorityDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, fmt.Errorf("create store dir: %w", err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return nil, fmt.Errorf("lock store dir perms: %w", err)
		}
	}
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve lease dir: %w", err)
	}
	resolvedAuthority, err := filepath.EvalSymlinks(authorityDir)
	if err != nil {
		return nil, fmt.Errorf("resolve authority dir: %w", err)
	}
	rel, err := filepath.Rel(resolvedDir, resolvedAuthority)
	if err != nil {
		return nil, fmt.Errorf("compare store dirs: %w", err)
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
		return nil, fmt.Errorf("%w: authority dir must be outside lease dir", ErrInvalidRequest)
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, fmt.Errorf("create block cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return &DiskStore{dir: resolvedDir, authorityDir: resolvedAuthority, aead: aead}, nil
}

func (d *DiskStore) Save(_ context.Context, state *leaseState) error {
	if state == nil {
		return fmt.Errorf("%w: state is required", ErrInvalidRequest)
	}
	leaseID := normalizeLeaseID(state.LeaseID)
	if leaseID == "" {
		return ErrInvalidLeaseID
	}
	if normalizeLeaseID(state.Current.LeaseID) != leaseID || state.Current.Epoch < 1 {
		return fmt.Errorf("%w: invalid current lease or epoch", ErrInvalidRequest)
	}

	return d.withLeaseLock(leaseID, func() error {
		old, err := d.loadLocked(leaseID)
		if err != nil && !errors.Is(err, ErrLeaseNotFound) {
			return err
		}
		if old == nil {
			if state.Current.Epoch != 1 {
				return fmt.Errorf("%w: first epoch must be 1", ErrStaleEpoch)
			}
		} else if state.Current.Epoch <= old.Current.Epoch || state.Current.Epoch != old.Current.Epoch+1 {
			return fmt.Errorf("%w: expected epoch %d, got %d", ErrStaleEpoch, old.Current.Epoch+1, state.Current.Epoch)
		}

		payload, err := json.Marshal(state)
		if err != nil {
			return err
		}
		nonce := make([]byte, d.aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}
		blob := append(nonce, d.aead.Seal(nil, nonce, payload, nil)...)

		path := d.pathForLease(leaseID)
		pending := path + ".pending"
		// A staged write without an updated checkpoint was never committed.
		if err := os.Remove(pending); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		file, err := os.OpenFile(pending, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if _, err := file.Write(blob); err != nil {
			_ = file.Close()
			_ = os.Remove(pending)
			return err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			_ = os.Remove(pending)
			return err
		}
		if err := file.Close(); err != nil {
			_ = os.Remove(pending)
			return err
		}

		// Publish the trusted high-water mark *before* the replayable blob.
		// A crash leaves either the old committed state or a recoverable
		// .pending blob, never an accepted lower epoch.
		checkpoint := leaseCheckpoint{
			LeaseID: leaseID,
			Epoch:   state.Current.Epoch,
			Digest:  sha256.Sum256(blob),
		}
		if err := d.writeCheckpoint(leaseID, checkpoint); err != nil {
			_ = os.Remove(pending)
			return err
		}
		if err := os.Rename(pending, path); err != nil {
			// Keep .pending: Load can complete the committed transaction.
			return err
		}
		return syncDirectory(d.dir)
	})
}

func (d *DiskStore) Load(_ context.Context, leaseID string) (*leaseState, error) {
	leaseID = normalizeLeaseID(leaseID)
	if leaseID == "" {
		return nil, ErrInvalidLeaseID
	}
	var state *leaseState
	err := d.withLeaseLock(leaseID, func() error {
		var loadErr error
		state, loadErr = d.loadLocked(leaseID)
		return loadErr
	})
	return state, err
}

func (d *DiskStore) loadLocked(leaseID string) (*leaseState, error) {
	path := d.pathForLease(leaseID)
	checkpoint, err := d.readCheckpoint(leaseID)
	if errors.Is(err, os.ErrNotExist) {
		if _, statErr := os.Stat(path); errors.Is(statErr, os.ErrNotExist) {
			return nil, ErrLeaseNotFound
		} else if statErr != nil {
			return nil, statErr
		}
		// Never trust an old file when its checkpoint is missing.
		return nil, fmt.Errorf("%w: missing lease checkpoint", ErrCorruptStore)
	}
	if err != nil {
		return nil, err
	}

	blob, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if sha256.Sum256(blob) != checkpoint.Digest || errors.Is(err, os.ErrNotExist) {
		pending := path + ".pending"
		staged, stageErr := os.ReadFile(pending)
		if stageErr == nil && sha256.Sum256(staged) == checkpoint.Digest {
			if err := os.Rename(pending, path); err != nil {
				return nil, err
			}
			if err := syncDirectory(d.dir); err != nil {
				return nil, err
			}
			blob = staged
		} else {
			if stageErr != nil && !errors.Is(stageErr, os.ErrNotExist) {
				return nil, stageErr
			}
			return nil, d.markCorrupt(path, errors.New("lease checkpoint mismatch"))
		}
	}
	nonceSize := d.aead.NonceSize()
	if len(blob) <= nonceSize {
		return nil, d.markCorrupt(path, errors.New("payload truncated"))
	}
	plaintext, err := d.aead.Open(nil, blob[:nonceSize], blob[nonceSize:], nil)
	if err != nil {
		return nil, d.markCorrupt(path, err)
	}
	var state leaseState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, d.markCorrupt(path, err)
	}
	if normalizeLeaseID(state.LeaseID) != leaseID ||
		normalizeLeaseID(state.Current.LeaseID) != leaseID ||
		state.Current.Epoch != checkpoint.Epoch {
		return nil, d.markCorrupt(path, errors.New("lease or epoch mismatch"))
	}
	return &state, nil
}

func (d *DiskStore) readCheckpoint(leaseID string) (leaseCheckpoint, error) {
	var checkpoint leaseCheckpoint
	data, err := os.ReadFile(d.pathForCheckpoint(leaseID))
	if err != nil {
		return checkpoint, err
	}
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		return checkpoint, fmt.Errorf("%w: invalid checkpoint: %v", ErrCorruptStore, err)
	}
	if checkpoint.LeaseID != leaseID || checkpoint.Epoch < 1 {
		return checkpoint, fmt.Errorf("%w: invalid checkpoint identity or epoch", ErrCorruptStore)
	}
	return checkpoint, nil
}

func (d *DiskStore) writeCheckpoint(leaseID string, checkpoint leaseCheckpoint) error {
	data, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(d.authorityDir, ".checkpoint-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), d.pathForCheckpoint(leaseID)); err != nil {
		return err
	}
	return syncDirectory(d.authorityDir)
}

func (d *DiskStore) withLeaseLock(leaseID string, fn func() error) error {
	file, err := os.OpenFile(d.pathForCheckpoint(leaseID)+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := lockLeaseFile(file); err != nil {
		return fmt.Errorf("lock lease checkpoint: %w", err)
	}
	defer unlockLeaseFile(file)
	return fn()
}

func syncDirectory(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
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

func (d *DiskStore) pathForCheckpoint(leaseID string) string {
	hash := sha256.Sum256([]byte(leaseID))
	return filepath.Join(d.authorityDir, fmt.Sprintf("%x.checkpoint", hash[:]))
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
