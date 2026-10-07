package cli

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeSinglePEM(t *testing.T, data []byte) *pem.Block {
	t.Helper()
	block, rest := pem.Decode(data)
	require.NotNil(t, block, "no PEM block found")
	assert.Empty(t, rest, "unexpected trailing data after PEM block")
	return block
}

// runCLI runs csrgen with args and returns exit code, stdout and stderr.
func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	code := Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// writeCertFor writes a self-signed PEM certificate for key to certPath.
func writeCertFor(t *testing.T, key crypto.Signer, certPath string) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
}

// writeCertForKeyFile writes a self-signed certificate for the PKCS#8 key in keyPath.
func writeCertForKeyFile(t *testing.T, keyPath, certPath string) {
	t.Helper()
	keyFile, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	parsed, err := x509.ParsePKCS8PrivateKey(decodeSinglePEM(t, keyFile).Bytes)
	require.NoError(t, err)
	writeCertFor(t, parsed.(crypto.Signer), certPath)
}

// sha256Values returns the values of the "SHA-256:" lines in check output.
func sha256Values(output string) []string {
	values := []string{}
	for _, line := range strings.Split(output, "\n") {
		_, value, found := strings.Cut(line, "SHA-256:")
		if found {
			values = append(values, strings.TrimSpace(value))
		}
	}
	return values
}

func TestRun(t *testing.T) {
	t.Run("default EC key and CSR", func(t *testing.T) {
		dir := t.TempDir()
		code, stdout, stderr := runCLI(t, "--out-dir", dir, "example.com", "--san", "www.example.com")
		require.Equal(t, 0, code, "stderr: %s", stderr)

		keyPath := filepath.Join(dir, "example_com.pem")
		csrPath := filepath.Join(dir, "example_com.csr")
		assert.Contains(t, stderr, keyPath)
		assert.Contains(t, stderr, csrPath)

		// stdout is exactly the CSR file, and nothing else.
		csrFile, err := os.ReadFile(csrPath)
		require.NoError(t, err)
		assert.Equal(t, string(csrFile), stdout)
		csrBlock := decodeSinglePEM(t, []byte(stdout))
		assert.Equal(t, "CERTIFICATE REQUEST", csrBlock.Type)

		keyFile, err := os.ReadFile(keyPath)
		require.NoError(t, err)
		keyBlock := decodeSinglePEM(t, keyFile)
		assert.Equal(t, "PRIVATE KEY", keyBlock.Type)
		parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		require.NoError(t, err)
		ecKey, ok := parsedKey.(*ecdsa.PrivateKey)
		require.True(t, ok, "expected *ecdsa.PrivateKey, got %T", parsedKey)
		assert.Equal(t, "P-256", ecKey.Curve.Params().Name)

		parsedCSR, err := x509.ParseCertificateRequest(csrBlock.Bytes)
		require.NoError(t, err)
		require.NoError(t, parsedCSR.CheckSignature())
		assert.True(t, ecKey.PublicKey.Equal(parsedCSR.PublicKey), "CSR must be for the written key")
		assert.Equal(t, "CN=example.com", parsedCSR.Subject.String())
		assert.Equal(t, []string{"example.com", "www.example.com"}, parsedCSR.DNSNames)
	})

	t.Run("RSA legacy key", func(t *testing.T) {
		dir := t.TempDir()
		code, _, stderr := runCLI(t, "--out-dir", dir, "--key", "rsa", "--legacy-key", "--org", "Example Ltd", "switch.local")
		require.Equal(t, 0, code, "stderr: %s", stderr)

		keyFile, err := os.ReadFile(filepath.Join(dir, "switch_local.pem"))
		require.NoError(t, err)
		keyBlock := decodeSinglePEM(t, keyFile)
		assert.Equal(t, "RSA PRIVATE KEY", keyBlock.Type)
		rsaKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		require.NoError(t, err)
		assert.Equal(t, 2048, rsaKey.N.BitLen())

		csrFile, err := os.ReadFile(filepath.Join(dir, "switch_local.csr"))
		require.NoError(t, err)
		parsedCSR, err := x509.ParseCertificateRequest(decodeSinglePEM(t, csrFile).Bytes)
		require.NoError(t, err)
		assert.Equal(t, x509.SHA256WithRSA, parsedCSR.SignatureAlgorithm)
		assert.True(t, rsaKey.PublicKey.Equal(parsedCSR.PublicKey.(*rsa.PublicKey)))
		assert.Equal(t, []string{"Example Ltd"}, parsedCSR.Subject.Organization)
	})

	t.Run("usage error exits 2 and writes nothing", func(t *testing.T) {
		dir := t.TempDir()
		code, stdout, stderr := runCLI(t, "--out-dir", dir, "--bits", "4096", "example.com")
		assert.Equal(t, 2, code)
		assert.Empty(t, stdout)
		assert.Contains(t, stderr, "usage: csrgen")

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("help exits 0", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "-h")
		assert.Equal(t, 0, code)
		assert.Empty(t, stdout)
		assert.Contains(t, stderr, "usage: csrgen")
		assert.Contains(t, stderr, "csrgen check", "main usage mentions the check subcommand")
	})

	t.Run("existing files are kept unless --force", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "example_com.pem")

		code, _, _ := runCLI(t, "--out-dir", dir, "example.com")
		require.Equal(t, 0, code)
		firstKey, err := os.ReadFile(keyPath)
		require.NoError(t, err)

		code, stdout, stderr := runCLI(t, "--out-dir", dir, "example.com")
		assert.Equal(t, 1, code)
		assert.Empty(t, stdout)
		assert.Contains(t, stderr, "--force")
		sameKey, err := os.ReadFile(keyPath)
		require.NoError(t, err)
		assert.Equal(t, firstKey, sameKey)

		code, _, stderr = runCLI(t, "--out-dir", dir, "--force", "example.com")
		require.Equal(t, 0, code, "stderr: %s", stderr)
		newKey, err := os.ReadFile(keyPath)
		require.NoError(t, err)
		assert.NotEqual(t, firstKey, newKey)
	})

	t.Run("missing output directory is created", func(t *testing.T) {
		outDir := filepath.Join(t.TempDir(), "certs", "2026")
		code, _, stderr := runCLI(t, "--out-dir", outDir, "example.com")
		require.Equal(t, 0, code, "stderr: %s", stderr)
		assert.FileExists(t, filepath.Join(outDir, "example_com.pem"))
		assert.FileExists(t, filepath.Join(outDir, "example_com.csr"))
	})

	t.Run("output directory that is a file exits 1", func(t *testing.T) {
		notADir := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(notADir, nil, 0o644))
		code, stdout, _ := runCLI(t, "--out-dir", notADir, "example.com")
		assert.Equal(t, 1, code)
		assert.Empty(t, stdout)
	})
}

func TestRunCheck(t *testing.T) {
	// setup generates example.com's key and CSR into a fresh directory.
	setup := func(t *testing.T) (string, string, string) {
		dir := t.TempDir()
		code, _, stderr := runCLI(t, "--out-dir", dir, "example.com")
		require.Equal(t, 0, code, "stderr: %s", stderr)
		return dir, filepath.Join(dir, "example_com.pem"), filepath.Join(dir, "example_com.crt")
	}

	t.Run("matching pair by common name", func(t *testing.T) {
		dir, keyPath, certPath := setup(t)
		writeCertForKeyFile(t, keyPath, certPath)

		code, stdout, stderr := runCLI(t, "check", "--out-dir", dir, "example.com")
		require.Equal(t, 0, code, "stderr: %s", stderr)
		assert.Contains(t, stdout, certPath)
		assert.Contains(t, stdout, keyPath)
		assert.Equal(t, 2, strings.Count(stdout, "ECDSA P-256"))
		assert.Contains(t, stdout, "OK:")

		sums := sha256Values(stdout)
		require.Len(t, sums, 2)
		assert.Len(t, sums[0], 64)
		assert.Equal(t, sums[0], sums[1])
	})

	t.Run("matching pair by paths", func(t *testing.T) {
		_, keyPath, certPath := setup(t)
		writeCertForKeyFile(t, keyPath, certPath)

		code, stdout, stderr := runCLI(t, "check", certPath, keyPath)
		require.Equal(t, 0, code, "stderr: %s", stderr)
		assert.Contains(t, stdout, "OK:")
	})

	t.Run("key type mismatch", func(t *testing.T) {
		_, keyPath, certPath := setup(t)
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		writeCertFor(t, rsaKey, certPath)

		code, stdout, _ := runCLI(t, "check", certPath, keyPath)
		assert.Equal(t, 1, code)
		assert.Contains(t, stdout, "MISMATCH")
		assert.Contains(t, stdout, "RSA 2048")
		assert.Contains(t, stdout, "ECDSA P-256")
		assert.NotContains(t, stdout, "OK:")
	})

	t.Run("same type, different key", func(t *testing.T) {
		_, keyPath, certPath := setup(t)
		otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		writeCertFor(t, otherKey, certPath)

		code, stdout, _ := runCLI(t, "check", certPath, keyPath)
		assert.Equal(t, 1, code)
		assert.Contains(t, stdout, "MISMATCH")
		sums := sha256Values(stdout)
		require.Len(t, sums, 2)
		assert.NotEqual(t, sums[0], sums[1])
	})

	t.Run("missing certificate exits 1", func(t *testing.T) {
		dir, _, certPath := setup(t)
		code, stdout, stderr := runCLI(t, "check", "--out-dir", dir, "example.com")
		assert.Equal(t, 1, code)
		assert.Empty(t, stdout)
		assert.Contains(t, stderr, certPath)
	})

	t.Run("usage error exits 2", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "check")
		assert.Equal(t, 2, code)
		assert.Empty(t, stdout)
		assert.Contains(t, stderr, "usage: csrgen check")
	})

	t.Run("help exits 0", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "check", "-h")
		assert.Equal(t, 0, code)
		assert.Empty(t, stdout)
		assert.Contains(t, stderr, "usage: csrgen check")
	})
}

// opensslSHA256 pipes input through "openssl sha256" and returns the hex digest.
func opensslSHA256(t *testing.T, opensslPath string, input []byte) string {
	t.Helper()
	cmd := exec.Command(opensslPath, "sha256")
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.Output()
	require.NoError(t, err)
	_, digest, found := strings.Cut(strings.TrimSpace(string(out)), "= ")
	require.True(t, found, "unexpected openssl sha256 output: %s", out)
	return digest
}

// TestOpenSSLAcceptsOutput checks the files with openssl itself, the same way
// a user would by hand. Skipped when openssl is not installed.
func TestOpenSSLAcceptsOutput(t *testing.T) {
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH")
	}

	cases := []struct {
		name string
		args []string
	}{
		{"EC P-256 PKCS#8", nil},
		{"EC P-384 PKCS#8", []string{"--curve", "p384"}},
		{"EC P-521 SEC1", []string{"--curve", "p521", "--legacy-key"}},
		{"RSA 2048 PKCS#8", []string{"--key", "rsa"}},
		{"RSA 2048 PKCS#1", []string{"--key", "rsa", "--legacy-key"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			args := append([]string{"--out-dir", dir, "--san", "10.0.0.1", "example.com"}, tc.args...)
			code, _, stderr := runCLI(t, args...)
			require.Equal(t, 0, code, "stderr: %s", stderr)

			keyPath := filepath.Join(dir, "example_com.pem")
			csrPath := filepath.Join(dir, "example_com.csr")

			out, err := exec.Command(opensslPath, "req", "-in", csrPath, "-verify", "-noout").CombinedOutput()
			require.NoError(t, err, "openssl req -verify: %s", out)

			out, err = exec.Command(opensslPath, "pkey", "-in", keyPath, "-check", "-noout").CombinedOutput()
			require.NoError(t, err, "openssl pkey -check: %s", out)

			// The CSR's public key must match the key file's public key.
			csrPub, err := exec.Command(opensslPath, "req", "-in", csrPath, "-pubkey", "-noout").Output()
			require.NoError(t, err)
			keyPub, err := exec.Command(opensslPath, "pkey", "-in", keyPath, "-pubout").Output()
			require.NoError(t, err)
			assert.Equal(t, string(keyPub), string(csrPub))

			// Have openssl issue a certificate from the CSR, then check that
			// csrgen check reports the same SHA-256 values as
			//   openssl x509 -in <crt> -noout -pubkey | openssl sha256
			//   openssl pkey -in <key> -pubout | openssl sha256
			certPath := filepath.Join(dir, "example_com.crt")
			out, err = exec.Command(opensslPath, "x509", "-req", "-in", csrPath, "-signkey", keyPath, "-days", "1", "-out", certPath).CombinedOutput()
			require.NoError(t, err, "openssl x509 -req: %s", out)
			certPub, err := exec.Command(opensslPath, "x509", "-in", certPath, "-noout", "-pubkey").Output()
			require.NoError(t, err)

			code, stdout, stderr := runCLI(t, "check", certPath, keyPath)
			require.Equal(t, 0, code, "stderr: %s", stderr)
			sums := sha256Values(stdout)
			require.Len(t, sums, 2)
			assert.Equal(t, opensslSHA256(t, opensslPath, certPub), sums[0], "certificate fingerprint")
			assert.Equal(t, opensslSHA256(t, opensslPath, keyPub), sums[1], "private key fingerprint")
		})
	}
}
