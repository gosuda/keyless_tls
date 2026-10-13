package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// openPrivateStoreDirectory pins each path component as it is traversed.
// This prevents an attacker from redirecting a later operation through a
// replaced ancestor. Existing directories must have safe ownership. Permissions are
// corrected only through the opened directory handle.
func openPrivateStoreDirectory(dir string) (*os.Root, error) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	for links := 0; links <= 8; links++ {
		root, redirected, err := walkStoreDirectory(absolute)
		if err != nil {
			return nil, err
		}
		if redirected == "" {
			return root, nil
		}
		absolute = redirected
	}
	return nil, fmt.Errorf("too many symbolic links in keyless dir")
}

func walkStoreDirectory(absolute string) (*os.Root, string, error) {
	volumeRoot := filepath.VolumeName(absolute) + string(filepath.Separator)
	relative, err := filepath.Rel(volumeRoot, absolute)
	if err != nil {
		return nil, "", err
	}
	if relative == "." {
		return nil, "", fmt.Errorf("keyless dir must not be a volume root")
	}
	parts := strings.Split(relative, string(filepath.Separator))

	root, err := os.OpenRoot(volumeRoot)
	if err != nil {
		return nil, "", err
	}
	defer func() {
		if root != nil {
			_ = root.Close()
		}
	}()

	current := volumeRoot
	for i, name := range parts {
		info, err := root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			if err := root.Mkdir(name, 0o700); err != nil {
				return nil, "", fmt.Errorf("create keyless path component %q: %w", name, err)
			}
			info, err = root.Lstat(name)
		}
		if err != nil {
			return nil, "", fmt.Errorf("inspect keyless path component %q: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if i == len(parts)-1 || current != volumeRoot || !trustedSystemSymlink(root, info) {
				return nil, "", fmt.Errorf("keyless path component %q is a symbolic link", name)
			}
			target, err := root.Readlink(name)
			if err != nil {
				return nil, "", err
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(current, target)
			}
			return nil, filepath.Join(target, filepath.Join(parts[i+1:]...)), nil
		}
		if !info.IsDir() {
			return nil, "", fmt.Errorf("keyless path component %q is not a directory", name)
		}

		next, err := root.OpenRoot(name)
		if err != nil {
			return nil, "", fmt.Errorf("open keyless path component %q: %w", name, err)
		}
		actual, err := next.Stat(".")
		if err != nil || !os.SameFile(info, actual) {
			_ = next.Close()
			if err != nil {
				return nil, "", err
			}
			return nil, "", fmt.Errorf("keyless path component %q changed during open", name)
		}
		_ = root.Close()
		root = next
		current = filepath.Join(current, name)
		if i == len(parts)-1 {
			if err := validateStoreDirectory(root, actual); err != nil {
				return nil, "", err
			}
			opened := root
			root = nil
			return opened, "", nil
		}
	}
	return nil, "", fmt.Errorf("keyless dir has no components")
}

func validateStoreDirectory(root *os.Root, info os.FileInfo) error {
	if !info.IsDir() {
		return fmt.Errorf("keyless store root is not a directory")
	}
	if err := validateStoreOwner(info); err != nil {
		return fmt.Errorf("keyless store root owner: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		// Adjust permissions through an opened directory, never a pathname.
		file, err := root.Open(".")
		if err != nil {
			return fmt.Errorf("open keyless dir for chmod: %w", err)
		}
		if err := file.Chmod(0o700); err != nil {
			_ = file.Close()
			return fmt.Errorf("lock keyless dir permissions: %w", err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close keyless dir after chmod: %w", err)
		}
	}
	return nil
}
