package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/the-old-england-manor/csrgen/internal/csr"
	"github.com/the-old-england-manor/csrgen/internal/keygen"
)

type config struct {
	key       keygen.Options
	legacyKey bool
	request   csr.Request
	outDir    string
	force     bool
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

const usageHeader = `usage: csrgen [flags] <common-name>
       csrgen check [--out-dir DIR] <common-name>
       csrgen check <certificate> <private-key>

Generates a private key and a CSR for <common-name>, writes them to
<out-dir>/<name>.pem and <out-dir>/<name>.csr, and prints the CSR to stdout.
<name> is the common name with "*" replaced by "wildcard" and other
punctuation by "_". Flags may come before or after <common-name>.
Run "csrgen check -h" for checking a certificate against its private key.

Flags:
`

// newFlagSet binds every flag to cfg, except --curve which is returned as a
// name to be parsed after the key type is known.
func newFlagSet(cfg *config, curveName *string) *flag.FlagSet {
	fs := flag.NewFlagSet("csrgen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&cfg.key.Type, "key", keygen.TypeEC, "key type: ec or rsa")
	fs.StringVar(curveName, "curve", "p256", "EC curve: p256, p384 or p521 (openssl names like prime256v1 also work)")
	fs.IntVar(&cfg.key.Bits, "bits", 2048, "RSA key size: 2048, 3072 or 4096")
	fs.BoolVar(&cfg.legacyKey, "legacy-key", false, "write the key as SEC1 (EC) or PKCS#1 (RSA) instead of PKCS#8")

	fs.Var((*stringList)(&cfg.request.SANs), "san", "additional subject alternative name, repeatable; IP addresses are detected")
	fs.StringVar(&cfg.request.Organization, "org", "", "organization (O)")
	fs.StringVar(&cfg.request.OrganizationalUnit, "ou", "", "organizational unit (OU)")
	fs.StringVar(&cfg.request.Country, "country", "", "two-letter country code (C)")
	fs.StringVar(&cfg.request.Province, "state", "", "state or province (ST)")
	fs.StringVar(&cfg.request.Locality, "locality", "", "locality or city (L)")

	fs.StringVar(&cfg.outDir, "out-dir", ".", "directory to write the key and CSR to (created if missing)")
	fs.BoolVar(&cfg.force, "force", false, "overwrite an existing key and CSR")
	return fs
}

func printUsage(w io.Writer) {
	cfg := config{}
	curveName := ""
	fs := newFlagSet(&cfg, &curveName)
	fs.SetOutput(w)
	fmt.Fprint(w, usageHeader)
	fs.PrintDefaults()
}

// parseArgs parses and validates the command line. Every error it returns,
// other than flag.ErrHelp, is a usage error.
func parseArgs(args []string) (config, error) {
	cfg := config{}
	curveName := ""
	fs := newFlagSet(&cfg, &curveName)

	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return config{}, err
	}

	if len(positional) != 1 {
		return config{}, fmt.Errorf("expected exactly one common name, got %d", len(positional))
	}
	cfg.request.CommonName = positional[0]
	if cfg.request.CommonName == "" {
		return config{}, errors.New("common name must not be empty")
	}

	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	switch cfg.key.Type {
	case keygen.TypeEC:
		if set["bits"] {
			return config{}, errors.New("--bits only applies to --key rsa")
		}
		curve, err := keygen.ParseCurve(curveName)
		if err != nil {
			return config{}, err
		}
		cfg.key.Curve = curve
	case keygen.TypeRSA:
		if set["curve"] {
			return config{}, errors.New("--curve only applies to --key ec")
		}
		switch cfg.key.Bits {
		case 2048, 3072, 4096:
		default:
			return config{}, fmt.Errorf("unsupported RSA key size %d (want 2048, 3072 or 4096)", cfg.key.Bits)
		}
	default:
		return config{}, fmt.Errorf("unsupported key type %q (want ec or rsa)", cfg.key.Type)
	}

	if cfg.request.Country != "" {
		if !isTwoLetters(cfg.request.Country) {
			return config{}, fmt.Errorf("--country must be a two-letter code, got %q", cfg.request.Country)
		}
		cfg.request.Country = strings.ToUpper(cfg.request.Country)
	}

	for _, san := range cfg.request.SANs {
		if san == "" {
			return config{}, errors.New("--san must not be empty")
		}
	}

	return cfg, nil
}

// parseInterspersed parses args with fs and returns the positional arguments.
// flag stops at the first positional argument, so parsing resumes after each
// one to allow flags anywhere on the command line.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	positional := []string{}
	for {
		err := fs.Parse(args)
		if err != nil {
			return nil, err
		}

		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

func isTwoLetters(s string) bool {
	if len(s) != 2 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}
