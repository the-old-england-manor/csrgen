package output

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fileMode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info.Mode().Perm()
}

func TestBaseName(t *testing.T) {
	tests := []struct {
		cn   string
		want string
	}{
		{"example.com", "example_com"},
		{"*.example.com", "wildcard_example_com"},
		{"my-host.example.com", "my-host_example_com"},
		{"10.0.0.1", "10_0_0_1"},
		{"2001:db8::1", "2001_db8__1"},
		{"../../etc/passwd", "______etc_passwd"},
		{`a\b:c?d"e<f>g|h`, "a_b_c_d_e_f_g_h"},
	}
	for _, tc := range tests {
		t.Run(tc.cn, func(t *testing.T) {
			assert.Equal(t, tc.want, baseName(tc.cn))
		})
	}
}

func TestPaths(t *testing.T) {
	dir := filepath.Join("some", "dir")
	keyPath, csrPath := Paths(dir, "*.example.com")
	assert.Equal(t, filepath.Join("some", "dir", "wildcard_example_com.pem"), keyPath)
	assert.Equal(t, filepath.Join("some", "dir", "wildcard_example_com.csr"), csrPath)
}

func TestCertPath(t *testing.T) {
	got := CertPath(filepath.Join("some", "dir"), "*.example.com")
	assert.Equal(t, filepath.Join("some", "dir", "wildcard_example_com.crt"), got)
}

func TestCheckTargets(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.pem")
	existing := filepath.Join(dir, "existing.csr")
	require.NoError(t, os.WriteFile(existing, []byte("old"), 0o644))

	t.Run("no files exist", func(t *testing.T) {
		assert.NoError(t, CheckTargets([]string{missing}, false))
	})

	t.Run("missing directory counts as no files", func(t *testing.T) {
		assert.NoError(t, CheckTargets([]string{filepath.Join(dir, "nope", "a.pem")}, false))
	})

	t.Run("existing file is refused", func(t *testing.T) {
		err := CheckTargets([]string{missing, existing}, false)
		assert.ErrorIs(t, err, fs.ErrExist)
		assert.Contains(t, err.Error(), existing)
	})

	t.Run("existing file allowed with force", func(t *testing.T) {
		assert.NoError(t, CheckTargets([]string{missing, existing}, true))
	})
}

func TestWrite(t *testing.T) {
	keyPEM := []byte("KEY DATA\n")
	csrPEM := []byte("CSR DATA\n")

	paths := func(t *testing.T) (string, string) {
		dir := t.TempDir()
		return filepath.Join(dir, "example.pem"), filepath.Join(dir, "example.csr")
	}

	t.Run("writes both files", func(t *testing.T) {
		keyPath, csrPath := paths(t)
		require.NoError(t, Write(keyPath, keyPEM, csrPath, csrPEM, false))

		gotKey, err := os.ReadFile(keyPath)
		require.NoError(t, err)
		assert.Equal(t, keyPEM, gotKey)

		gotCSR, err := os.ReadFile(csrPath)
		require.NoError(t, err)
		assert.Equal(t, csrPEM, gotCSR)

		if runtime.GOOS != "windows" {
			assert.Equal(t, fs.FileMode(0o600), fileMode(t, keyPath))
		}
	})

	t.Run("creates missing directories", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "certs", "2026")
		keyPath, csrPath := filepath.Join(dir, "example.pem"), filepath.Join(dir, "example.csr")
		require.NoError(t, Write(keyPath, keyPEM, csrPath, csrPEM, false))
		assert.FileExists(t, keyPath)
		assert.FileExists(t, csrPath)
	})

	t.Run("does not clobber an existing key without force", func(t *testing.T) {
		keyPath, csrPath := paths(t)
		require.NoError(t, os.WriteFile(keyPath, []byte("precious"), 0o600))

		err := Write(keyPath, keyPEM, csrPath, csrPEM, false)
		assert.ErrorIs(t, err, fs.ErrExist)

		got, err := os.ReadFile(keyPath)
		require.NoError(t, err)
		assert.Equal(t, []byte("precious"), got)
	})

	t.Run("force overwrites and tightens key mode", func(t *testing.T) {
		keyPath, csrPath := paths(t)
		require.NoError(t, os.WriteFile(keyPath, []byte("old key, longer than the new one"), 0o644))
		require.NoError(t, os.WriteFile(csrPath, []byte("old csr, longer than the new one"), 0o644))

		require.NoError(t, Write(keyPath, keyPEM, csrPath, csrPEM, true))

		gotKey, err := os.ReadFile(keyPath)
		require.NoError(t, err)
		assert.Equal(t, keyPEM, gotKey)

		gotCSR, err := os.ReadFile(csrPath)
		require.NoError(t, err)
		assert.Equal(t, csrPEM, gotCSR)

		if runtime.GOOS != "windows" {
			assert.Equal(t, fs.FileMode(0o600), fileMode(t, keyPath))
		}
	})

	t.Run("CSR write failure removes the new key", func(t *testing.T) {
		keyPath, csrPath := paths(t)
		// A directory at the CSR path makes the CSR write fail.
		require.NoError(t, os.Mkdir(csrPath, 0o755))

		err := Write(keyPath, keyPEM, csrPath, csrPEM, false)
		assert.Error(t, err)

		_, statErr := os.Stat(keyPath)
		assert.ErrorIs(t, statErr, fs.ErrNotExist)
	})
}
