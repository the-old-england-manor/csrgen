package cli

import (
	"errors"
	"flag"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseArgs(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := parseArgs([]string{"example.com"})
		require.NoError(t, err)
		assert.Equal(t, "example.com", cfg.request.CommonName)
		assert.Equal(t, "ec", cfg.key.Type)
		assert.Equal(t, "P-256", cfg.key.Curve.Params().Name)
		assert.False(t, cfg.legacyKey)
		assert.Equal(t, ".", cfg.outDir)
		assert.False(t, cfg.force)
		assert.Empty(t, cfg.request.SANs)
	})

	t.Run("flags after the CN are parsed", func(t *testing.T) {
		cfg, err := parseArgs([]string{
			"example.com",
			"--san", "www.example.com",
			"--curve", "secp384r1",
			"--san", "10.0.0.1",
		})
		require.NoError(t, err)
		assert.Equal(t, "example.com", cfg.request.CommonName)
		assert.Equal(t, "P-384", cfg.key.Curve.Params().Name)
		assert.Equal(t, []string{"www.example.com", "10.0.0.1"}, cfg.request.SANs)
	})

	t.Run("RSA defaults to 2048 bits", func(t *testing.T) {
		cfg, err := parseArgs([]string{"--key", "rsa", "example.com"})
		require.NoError(t, err)
		assert.Equal(t, "rsa", cfg.key.Type)
		assert.Equal(t, 2048, cfg.key.Bits)
	})

	t.Run("RSA bits after the CN", func(t *testing.T) {
		cfg, err := parseArgs([]string{"--key", "rsa", "example.com", "--bits", "4096"})
		require.NoError(t, err)
		assert.Equal(t, 4096, cfg.key.Bits)
	})

	t.Run("subject and output flags", func(t *testing.T) {
		cfg, err := parseArgs([]string{
			"--org", "Example Ltd",
			"--ou", "IT Dept",
			"--country", "gb",
			"--state", "England",
			"--locality", "London",
			"--out-dir", "/tmp/out",
			"--legacy-key",
			"--force",
			"example.com",
		})
		require.NoError(t, err)
		assert.Equal(t, "Example Ltd", cfg.request.Organization)
		assert.Equal(t, "IT Dept", cfg.request.OrganizationalUnit)
		assert.Equal(t, "GB", cfg.request.Country, "country is upper-cased")
		assert.Equal(t, "England", cfg.request.Province)
		assert.Equal(t, "London", cfg.request.Locality)
		assert.Equal(t, "/tmp/out", cfg.outDir)
		assert.True(t, cfg.legacyKey)
		assert.True(t, cfg.force)
	})

	t.Run("help", func(t *testing.T) {
		_, err := parseArgs([]string{"-h"})
		assert.ErrorIs(t, err, flag.ErrHelp)
	})

	invalid := []struct {
		name string
		args []string
	}{
		{"no CN", []string{}},
		{"two CNs", []string{"a.example.com", "b.example.com"}},
		{"empty CN", []string{""}},
		{"unknown flag", []string{"--nope", "example.com"}},
		{"unknown key type", []string{"--key", "dsa", "example.com"}},
		{"unknown curve", []string{"--curve", "p999", "example.com"}},
		{"curve with RSA", []string{"--key", "rsa", "--curve", "p256", "example.com"}},
		{"bits with EC", []string{"--bits", "4096", "example.com"}},
		{"bits with explicit EC", []string{"--key", "ec", "example.com", "--bits", "2048"}},
		{"unsupported RSA size", []string{"--key", "rsa", "--bits", "1024", "example.com"}},
		{"country too long", []string{"--country", "GBR", "example.com"}},
		{"country not letters", []string{"--country", "1A", "example.com"}},
		{"empty SAN", []string{"--san", "", "example.com"}},
	}
	for _, tc := range invalid {
		t.Run("invalid: "+tc.name, func(t *testing.T) {
			_, err := parseArgs(tc.args)
			require.Error(t, err)
			assert.False(t, errors.Is(err, flag.ErrHelp))
		})
	}
}

func TestParseCheckArgs(t *testing.T) {
	valid := []struct {
		name     string
		args     []string
		wantCert string
		wantKey  string
	}{
		{"common name", []string{"example.com"}, "example_com.crt", "example_com.pem"},
		{"common name with out-dir", []string{"--out-dir", "certs", "example.com"}, filepath.Join("certs", "example_com.crt"), filepath.Join("certs", "example_com.pem")},
		{"out-dir after common name", []string{"example.com", "--out-dir", "certs"}, filepath.Join("certs", "example_com.crt"), filepath.Join("certs", "example_com.pem")},
		{"explicit paths", []string{"vendor/site.crt", "keys/site.key"}, "vendor/site.crt", "keys/site.key"},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseCheckArgs(tc.args)
			require.NoError(t, err)
			assert.Equal(t, tc.wantCert, cfg.certPath)
			assert.Equal(t, tc.wantKey, cfg.keyPath)
		})
	}

	t.Run("help", func(t *testing.T) {
		_, err := parseCheckArgs([]string{"-h"})
		assert.ErrorIs(t, err, flag.ErrHelp)
	})

	invalid := []struct {
		name string
		args []string
	}{
		{"no arguments", []string{}},
		{"three arguments", []string{"a.crt", "a.pem", "extra"}},
		{"empty common name", []string{""}},
		{"out-dir with explicit paths", []string{"--out-dir", "certs", "a.crt", "a.pem"}},
		{"unknown flag", []string{"--nope", "example.com"}},
	}
	for _, tc := range invalid {
		t.Run("invalid: "+tc.name, func(t *testing.T) {
			_, err := parseCheckArgs(tc.args)
			require.Error(t, err)
			assert.False(t, errors.Is(err, flag.ErrHelp))
		})
	}
}
