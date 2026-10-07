// Package cli implements the csrgen command line.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/the-old-england-manor/csrgen/internal/csr"
	"github.com/the-old-england-manor/csrgen/internal/keygen"
	"github.com/the-old-england-manor/csrgen/internal/output"
)

// Run executes csrgen with args (without the program name) and returns the
// process exit code: 0 on success, 2 on usage errors, 1 on everything else
// (including a key that does not match its certificate for "check").
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "check" {
		return runCheck(args[1:], stdout, stderr)
	}

	cfg, err := parseArgs(args)
	if errors.Is(err, flag.ErrHelp) {
		printUsage(stderr)
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "csrgen: %v\n\n", err)
		printUsage(stderr)
		return 2
	}

	err = generate(cfg, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "csrgen: %v\n", err)
		return 1
	}
	return 0
}

// generate creates the key and CSR, writes both files, and prints the CSR.
func generate(cfg config, stdout, stderr io.Writer) error {
	keyPath, csrPath := output.Paths(cfg.outDir, cfg.request.CommonName)

	err := output.CheckTargets([]string{keyPath, csrPath}, cfg.force)
	if err != nil {
		return err
	}

	key, err := keygen.Generate(cfg.key)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	keyPEM, err := keygen.EncodePEM(key, cfg.legacyKey)
	if err != nil {
		return fmt.Errorf("encoding key: %w", err)
	}

	csrPEM, err := csr.Create(key, cfg.request)
	if err != nil {
		return fmt.Errorf("creating CSR: %w", err)
	}

	err = output.Write(keyPath, keyPEM, csrPath, csrPEM, cfg.force)
	if err != nil {
		return err
	}

	fmt.Fprintf(stderr, "Wrote private key: %s\n", keyPath)
	fmt.Fprintf(stderr, "Wrote CSR:         %s\n", csrPath)
	_, err = stdout.Write(csrPEM)
	return err
}
