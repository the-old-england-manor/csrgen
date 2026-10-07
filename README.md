# csrgen

A small Go utility that generates a private key and a Certificate Signing Request (CSR) in one step, and later checks that the certificate you get back matches that key. ECDSA P-256 by default, RSA when you need it.

## What it does

Given a common name, it:

- generates a new private key (unencrypted, like `openssl -nodes`)
- creates a CSR signed by that key, with the common name in the subject **and** in the Subject Alternative Name (SAN) list
- writes `<name>.pem` (key, mode `0600`) and `<name>.csr` to the output directory
- prints the CSR to stdout, ready to paste into a CA or vendor portal

`<name>` is the common name with `*` replaced by `wildcard` and every other punctuation character replaced by `_`, so `example.com` becomes `example_com` and `*.example.com` becomes `wildcard_example_com`.

Once the CA sends the certificate back, `csrgen check` confirms it belongs to your private key (see [Checking a certificate against its key](#checking-a-certificate-against-its-key)).

## Why this exists

Generating a key and CSR with openssl looks like this:

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout example_com.pem -out example_com.csr \
  -subj "/CN=example.com"; cat example_com.csr
```

It's long and easy to fat-finger. `csrgen example.com` makes it easier.

## Requirements

- Go 1.27.1+ (to build or `go install`)

## Install

```bash
go install github.com/the-old-england-manor/csrgen@latest
```

Replace `@latest` with a version tag (e.g. `@v0.1.0`) to pin to a specific release. Prebuilt binaries for Linux, macOS and Windows are attached to each GitHub release.

## Usage

```
csrgen [flags] <common-name>
```

Flags may come before or after the common name.

| Flag | Default | Description |
| --- | --- | --- |
| `--key` | `ec` | Key type: `ec` or `rsa` |
| `--curve` | `p256` | EC curve: `p256`, `p384`, `p521`. openssl names (`prime256v1`, `secp384r1`, `secp521r1`) also work. EC only |
| `--bits` | `2048` | RSA key size: `2048`, `3072`, `4096`. RSA only |
| `--legacy-key` | off | Write the key as SEC1 (`EC PRIVATE KEY`) or PKCS#1 (`RSA PRIVATE KEY`) instead of PKCS#8 |
| `--san` | | Additional SAN, repeatable. IP addresses are detected automatically |
| `--org` | | Organization (O) |
| `--ou` | | Organizational unit (OU) |
| `--country` | | Two-letter country code (C) |
| `--state` | | State or province (ST) |
| `--locality` | | Locality or city (L) |
| `--out-dir` | `.` | Directory to write the key and CSR to |
| `--force` | off | Overwrite an existing key and CSR |

Status messages go to stderr; stdout contains only the CSR, so it can be piped (e.g. `csrgen example.com | pbcopy`).

Exit codes: `0` success, `1` runtime error (e.g. files already exist), `2` invalid usage.

### Examples

```bash
# ECDSA P-256, same as the openssl command above
csrgen example.com

# Extra SANs (DNS names and IPs)
csrgen example.com --san www.example.com --san 10.0.0.1

# Wildcard → wildcard_example_com.pem / .csr
csrgen '*.example.com' --san example.com

# ECDSA P-384
csrgen --curve p384 example.com

# RSA 4096 with organization details (OV/EV certificates)
csrgen --key rsa --bits 4096 --org "Example Ltd" --country GB --locality London example.com

# Legacy key format for devices that reject PKCS#8
csrgen --legacy-key switch01.example.com

# Write somewhere else, replacing any previous key and CSR
csrgen --out-dir ./certs --force example.com
```

**Example output:**

```
$ csrgen example.com
Wrote private key: example_com.pem
Wrote CSR:         example_com.csr
-----BEGIN CERTIFICATE REQUEST-----
MIH6MIGhAgEAMBYxFDASBgNVBAMTC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYI
...
-----END CERTIFICATE REQUEST-----
```

## Checking a certificate against its key

```
csrgen check [--out-dir DIR] <common-name>
csrgen check <certificate> <private-key>
```

Compares the public key inside the certificate with the one derived from the private key, and reports the key type and a SHA-256 fingerprint of each. With a common name it reads `<out-dir>/<name>.crt` and `<out-dir>/<name>.pem`, so save the certificate from your CA next to the key csrgen wrote; with two paths it uses them as given.

The fingerprints are exactly what this openssl pipeline prints, with SHA-256 in place of MD5:

```bash
openssl x509 -in example_com.crt -noout -pubkey | openssl sha256
openssl pkey -in example_com.pem -pubout | openssl sha256
```

The certificate may be PEM (the first certificate in a chain file is used) or DER. The key may be PKCS#8, SEC1 or PKCS#1; encrypted keys are not supported.

Exit codes: `0` match, `1` mismatch or unreadable file, `2` invalid usage.

```
$ csrgen check example.com
Certificate: example_com.crt
  Key type:  ECDSA P-256
  SHA-256:   a69d66133bfb9e2275a130fd2ea784ae83fdd20fa473594db2bc1e44942a411b
Private key: example_com.pem
  Key type:  ECDSA P-256
  SHA-256:   a69d66133bfb9e2275a130fd2ea784ae83fdd20fa473594db2bc1e44942a411b
OK: private key matches certificate

$ csrgen check example_com.crt other_example_com.pem
...
MISMATCH: private key does not match certificate: key type mismatch: certificate is ECDSA P-256, private key is RSA 2048
```

## Private key formats

|               | PKCS#8 (default)           | SEC1 (`--legacy-key`, EC)  | PKCS#1 (`--legacy-key`, RSA) |
| ------------- | -------------------------- | -------------------------- | ---------------------------- |
| PEM header    | `BEGIN PRIVATE KEY`        | `BEGIN EC PRIVATE KEY`     | `BEGIN RSA PRIVATE KEY`      |
| Key types     | Any (algorithm OID inside) | EC only                    | RSA only                     |
| Produced by   | openssl 3.x by default     | openssl 1.x `ecparam`      | openssl 1.x `genrsa`         |

## Development

```bash
make test       # fmt, vet, tests with coverage
make build-all  # cross-compile into ./bin
```

```
main.go             entry point only
internal/cli        flags, validation, exit codes
internal/keygen     key generation and private key PEM encoding
internal/csr        CSR construction (subject, SANs)
internal/output     file naming, overwrite protection, writing
internal/check      certificate / private key fingerprint comparison
```

The test suite includes an integration test that verifies the generated files with `openssl req -verify` and `openssl pkey -check`, and confirms `csrgen check` reports the same SHA-256 values as the openssl pipeline above; it is skipped when openssl is not installed.

## License

MIT — see [LICENSE](LICENSE)
