//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package lifecycle

import (
	"os"
	"syscall"
)

func lockLeaseFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
}

func unlockLeaseFile(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
