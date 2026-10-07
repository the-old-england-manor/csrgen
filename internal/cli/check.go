package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/the-old-england-manor/csrgen/internal/check"
	"github.com/the-old-england-manor/csrgen/internal/output"
)

const checkUsageHeader = `usage: csrgen check [--out-dir DIR] <common-name>
       csrgen check <certificate> <private-key>

Checks that a certificate and a private key belong together by comparing the
SHA-256 of their public keys. The values are the same as
  openssl x509 -in <certificate> -noout -pubkey | openssl sha256
  openssl pkey -in <private-key> -pubout | openssl sha256
With a common name, <out-dir>/<name>.crt and <out-dir>/<name>.pem are used.
Exits 0 when they match and 1 when they do not.

Flags:
`

type checkConfig struct {
	certPath string
	keyPath  string
}

func newCheckFlagSet(outDir *string) *flag.FlagSet {
	fs := flag.NewFlagSet("csrgen check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(outDir, "out-dir", ".", "directory holding <name>.crt and <name>.pem (common-name form only)")
	return fs
}

func printCheckUsage(w io.Writer) {
	outDir := ""
	fs := newCheckFlagSet(&outDir)
	fs.SetOutput(w)
	fmt.Fprint(w, checkUsageHeader)
	fs.PrintDefaults()
}

// parseCheckArgs accepts either a common name (files derived from it inside
// --out-dir) or explicit certificate and private key paths.
func parseCheckArgs(args []string) (checkConfig, error) {
	outDir := ""
	fs := newCheckFlagSet(&outDir)

	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return checkConfig{}, err
	}

	outDirSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "out-dir" {
			outDirSet = true
		}
	})

	switch len(positional) {
	case 1:
		cn := positional[0]
		if cn == "" {
			return checkConfig{}, errors.New("common name must not be empty")
		}
		keyPath, _ := output.Paths(outDir, cn)
		return checkConfig{certPath: output.CertPath(outDir, cn), keyPath: keyPath}, nil
	case 2:
		if outDirSet {
			return checkConfig{}, errors.New("--out-dir only applies to the common-name form")
		}
		return checkConfig{certPath: positional[0], keyPath: positional[1]}, nil
	default:
		return checkConfig{}, fmt.Errorf("expected a common name, or a certificate and a private key; got %d arguments", len(positional))
	}
}

// runCheck executes "csrgen check" and returns the process exit code.
func runCheck(args []string, stdout, stderr io.Writer) int {
	cfg, err := parseCheckArgs(args)
	if errors.Is(err, flag.ErrHelp) {
		printCheckUsage(stderr)
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "csrgen check: %v\n\n", err)
		printCheckUsage(stderr)
		return 2
	}

	certInfo, keyInfo, err := inspect(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "csrgen check: %v\n", err)
		return 1
	}

	printKeyInfo(stdout, "Certificate:", cfg.certPath, certInfo)
	printKeyInfo(stdout, "Private key:", cfg.keyPath, keyInfo)

	err = check.Match(certInfo, keyInfo)
	if err != nil {
		fmt.Fprintf(stdout, "MISMATCH: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "OK: private key matches certificate")
	return 0
}

// inspect reads both files and describes their public keys.
func inspect(cfg checkConfig) (check.KeyInfo, check.KeyInfo, error) {
	certData, err := os.ReadFile(cfg.certPath)
	if err != nil {
		return check.KeyInfo{}, check.KeyInfo{}, err
	}
	certInfo, err := check.FromCertificate(certData)
	if err != nil {
		return check.KeyInfo{}, check.KeyInfo{}, fmt.Errorf("%s: %w", cfg.certPath, err)
	}

	keyData, err := os.ReadFile(cfg.keyPath)
	if err != nil {
		return check.KeyInfo{}, check.KeyInfo{}, err
	}
	keyInfo, err := check.FromPrivateKey(keyData)
	if err != nil {
		return check.KeyInfo{}, check.KeyInfo{}, fmt.Errorf("%s: %w", cfg.keyPath, err)
	}

	return certInfo, keyInfo, nil
}

func printKeyInfo(w io.Writer, label, path string, info check.KeyInfo) {
	fmt.Fprintf(w, "%s %s\n", label, path)
	fmt.Fprintf(w, "  Key type:  %s\n", info.Type)
	fmt.Fprintf(w, "  SHA-256:   %s\n", info.SHA256)
}
