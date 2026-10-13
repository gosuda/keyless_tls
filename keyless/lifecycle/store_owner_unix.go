//go:build unix

package lifecycle

import (
	"fmt"
	"os"
	"syscall"
)

func validateStoreOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine filesystem owner")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("owned by uid %d, expected uid %d", stat.Uid, os.Geteuid())
	}
	return nil
}

func trustedSystemSymlink(root *os.Root, link os.FileInfo) bool {
	parent, err := root.Stat(".")
	if err != nil || parent.Mode().Perm()&0o022 != 0 {
		return false
	}
	parentStat, parentOK := parent.Sys().(*syscall.Stat_t)
	linkStat, linkOK := link.Sys().(*syscall.Stat_t)
	return parentOK && linkOK && parentStat.Uid == 0 && linkStat.Uid == 0
}
