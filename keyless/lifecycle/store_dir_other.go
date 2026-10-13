//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package lifecycle

import (
	"errors"
	"os"
)

// Ownership and ACL validation require platform-specific APIs on these targets.
// Rooted, exclusive file creation still prevents the reported symlink clobber.
func validateStoreDirectory(info os.FileInfo, _ bool) error {
	if !info.IsDir() {
		return errors.New("not a directory")
	}
	return nil
}
