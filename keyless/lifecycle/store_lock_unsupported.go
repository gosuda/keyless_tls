//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package lifecycle

import (
	"errors"
	"os"
)

func lockLeaseFile(_ *os.File) error {
	return errors.New("rollback-protected disk store requires supported POSIX file locks")
}

func unlockLeaseFile(_ *os.File) {}
