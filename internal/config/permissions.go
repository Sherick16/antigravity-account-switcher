package config

import (
	"fmt"
	"os"
)

// EnsurePrivateDir creates or repairs an application data directory so that
// credentials and database sidecars cannot be read by other users.
func EnsurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create private directory %s: %w", path, err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private directory %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("private directory path is not a directory: %s", path)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("restrict private directory %s: %w", path, err)
	}
	return VerifyPrivateDir(path)
}

// VerifyPrivateDir checks that an existing directory is usable only by its owner.
// It intentionally does not change permissions, so callers can safely use it for
// user-selected paths outside the application's own data directory.
func VerifyPrivateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private directory %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("private directory path is not a directory: %s", path)
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("directory %s has permissions %04o; make it private with chmod 700 or choose another database path", path, info.Mode().Perm())
	}
	return nil
}

// EnsurePrivateFile creates or repairs a credential-bearing regular file with
// owner-only permissions.
func EnsurePrivateFile(path string) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		file, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if createErr != nil && !os.IsExist(createErr) {
			return fmt.Errorf("create private file %s: %w", path, createErr)
		}
		if file != nil {
			if closeErr := file.Close(); closeErr != nil {
				return fmt.Errorf("close private file %s: %w", path, closeErr)
			}
		}
	}
	return RepairPrivateFile(path)
}

// RepairPrivateFile restricts an existing regular file to its owner. Missing
// files are left for the caller to create.
func RepairPrivateFile(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect private file %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("private file path is not a regular file: %s", path)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict private file %s: %w", path, err)
	}
	return nil
}
