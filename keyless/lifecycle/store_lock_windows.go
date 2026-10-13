//go:build windows

package lifecycle

import (
	"errors"
	"os"
)

// DiskStore deliberately fails closed where its durable interprocess locking
// and directory fsync guarantees are not supported.
func lockLeaseFile(_ *os.File) error {
	return errors.New("rollback-protected disk store requires POSIX file locks")
}

func unlockLeaseFile(_ *os.File) {}
