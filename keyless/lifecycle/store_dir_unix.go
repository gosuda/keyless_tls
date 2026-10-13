//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// validateStoreDirectory requires a private, process-owned store.
// Ancestors may be root-owned; a root-owned sticky directory such as /tmp
// safely protects entries owned by other users.
func validateStoreDirectory(info os.FileInfo, final bool) error {
	if !info.IsDir() {
		return errors.New("not a directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot establish directory ownership")
	}
	uid := stat.Uid
	euid := uint32(os.Geteuid())
	mode := info.Mode()

	if final {
		if uid != euid {
			return fmt.Errorf("directory owner %d differs from process owner %d", uid, euid)
		}
		if mode.Perm()&0o022 != 0 {
			return fmt.Errorf("store directory is writable by group or others: %v", mode)
		}
		return nil
	}

	if uid != 0 && uid != euid {
		return fmt.Errorf("ancestor directory is owned by untrusted user %d", uid)
	}
	if mode.Perm()&0o022 != 0 && (uid != 0 || mode&os.ModeSticky == 0) {
		return fmt.Errorf("ancestor directory is writable by other users: %v", mode)
	}
	return nil
}
