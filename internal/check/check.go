// Package check compares the public key in a certificate with a private key.
//
// Fingerprints are the SHA-256 of the PEM-encoded public key, so they equal
//
//	openssl x509 -in <cert> -noout -pubkey | openssl sha256
//	openssl pkey -in <key> -pubout | openssl sha256
package check

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// ErrMismatch is returned by Match when the keys differ.
var ErrMismatch = errors.New("private key does not match certificate")

// KeyInfo describes a public key.
type KeyInfo struct {
	Type   string // e.g. "ECDSA P-256", "RSA 2048"
	SHA256 string // hex SHA-256 of the PEM-encoded public key
}

// FromCertificate returns the public key info of a certificate. data may be
// PEM (the first CERTIFICATE block is used, so chains work) or raw DER.
func FromCertificate(data []byte) (KeyInfo, error) {
	rest := data
	sawPEM := false
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		sawPEM = true
		rest = remaining

		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return KeyInfo{}, fmt.Errorf("parsing certificate: %w", err)
		}
		return describe(cert.PublicKey)
	}

	if sawPEM {
		return KeyInfo{}, errors.New("no CERTIFICATE PEM block found")
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return KeyInfo{}, fmt.Errorf("not a PEM or DER certificate: %w", err)
	}
	return describe(cert.PublicKey)
}

// FromPrivateKey returns the public key info of a PEM private key in PKCS#8,
// SEC1 or PKCS#1 form. Other PEM blocks (e.g. EC PARAMETERS) are skipped.
// Encrypted keys are not supported.
func FromPrivateKey(data []byte) (KeyInfo, error) {
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return KeyInfo{}, errors.New("no private key PEM block found")
		}
		rest = remaining

		if block.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
			return KeyInfo{}, errors.New("encrypted private keys are not supported; decrypt it first with openssl pkey")
		}

		key, err := parsePrivateKey(block)
		if err != nil {
			return KeyInfo{}, fmt.Errorf("parsing %s: %w", block.Type, err)
		}
		if key == nil {
			continue
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			return KeyInfo{}, fmt.Errorf("unsupported private key type %T", key)
		}
		return describe(signer.Public())
	}
}

// parsePrivateKey returns nil, nil for blocks that are not private keys.
func parsePrivateKey(block *pem.Block) (any, error) {
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, nil
	}
}

// Match returns nil when cert and key are the same public key, and an error
// wrapping ErrMismatch otherwise.
func Match(cert, key KeyInfo) error {
	if cert.SHA256 == key.SHA256 {
		return nil
	}
	if cert.Type != key.Type {
		return fmt.Errorf("%w: key type mismatch: certificate is %s, private key is %s", ErrMismatch, cert.Type, key.Type)
	}
	return fmt.Errorf("%w: both are %s but the public keys differ", ErrMismatch, cert.Type)
}

func describe(pub crypto.PublicKey) (KeyInfo, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return KeyInfo{}, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	sum := sha256.Sum256(pemBytes)
	return KeyInfo{Type: keyType(pub), SHA256: hex.EncodeToString(sum[:])}, nil
}

func keyType(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", pub)
	}
}
