// Package output names, checks and writes the key and CSR files.
package output

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Paths returns the key and CSR paths for cn inside dir.
func Paths(dir, cn string) (keyPath, csrPath string) {
	base := filepath.Join(dir, baseName(cn))
	return base + ".pem", base + ".csr"
}

// CertPath returns the path where the certificate for cn is expected inside
// dir, next to the key from Paths.
func CertPath(dir, cn string) string {
	return filepath.Join(dir, baseName(cn)) + ".crt"
}

// baseName turns a CN into a file name that is safe on every OS: "*" becomes
// "wildcard" and anything outside [A-Za-z0-9-] becomes "_".
func baseName(cn string) string {
	cn = strings.ReplaceAll(cn, "*", "wildcard")
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			return r
		default:
			return '_'
		}
	}, cn)
}

// CheckTargets fails if any path already exists, unless force is set.
func CheckTargets(paths []string, force bool) error {
	if force {
		return nil
	}
	for _, path := range paths {
		_, err := os.Stat(path)
		if err == nil {
			return fmt.Errorf("%s: %w (use --force to overwrite)", path, fs.ErrExist)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Write creates any missing directories, then writes the key (0600) and the
// CSR (0644). Without force, files are created exclusively so an existing key
// is never overwritten. If the CSR cannot be written, the key just written is
// removed.
func Write(keyPath string, keyPEM []byte, csrPath string, csrPEM []byte, force bool) error {
	for _, dir := range []string{filepath.Dir(keyPath), filepath.Dir(csrPath)} {
		err := os.MkdirAll(dir, 0o755)
		if err != nil {
			return err
		}
	}

	err := writeFile(keyPath, keyPEM, 0o600, force)
	if err != nil {
		return err
	}

	err = writeFile(csrPath, csrPEM, 0o644, force)
	if err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	return nil
}

func writeFile(path string, data []byte, perm fs.FileMode, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}

	f, err := os.OpenFile(path, flags, perm)
	if err != nil {
		return err
	}

	// OpenFile only applies perm to new files; reset it when overwriting.
	if force {
		err = f.Chmod(perm)
		if err != nil {
			f.Close()
			return err
		}
	}

	_, err = f.Write(data)
	if err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
