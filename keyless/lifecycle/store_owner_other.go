//go:build !unix

package lifecycle

import "os"

// On Windows, the effective access policy comes from directory ACLs rather
// than Unix owner and permission bits. Root confines operations to the opened
// directory, and O_EXCL prevents following an existing temporary-file link.
func validateStoreOwner(_ os.FileInfo) error { return nil }

func trustedSystemSymlink(_ *os.Root, _ os.FileInfo) bool { return false }
