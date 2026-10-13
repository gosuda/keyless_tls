//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

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
