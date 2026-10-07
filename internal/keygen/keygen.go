// Package keygen generates private keys and encodes them as PEM.
package keygen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// Supported key types.
const (
	TypeEC  = "ec"
	TypeRSA = "rsa"
)

// Options selects the kind of key Generate creates. Curve is used for TypeEC,
// Bits for TypeRSA.
type Options struct {
	Type  string
	Curve elliptic.Curve
	Bits  int
}

// ParseCurve maps a curve name (Go-style or openssl-style, case-insensitive)
// to an elliptic.Curve.
func ParseCurve(name string) (elliptic.Curve, error) {
	switch strings.ToLower(name) {
	case "p256", "p-256", "prime256v1":
		return elliptic.P256(), nil
	case "p384", "p-384", "secp384r1":
		return elliptic.P384(), nil
	case "p521", "p-521", "secp521r1":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve %q (want p256, p384 or p521)", name)
	}
}

// Generate creates a new private key.
func Generate(opts Options) (crypto.Signer, error) {
	switch opts.Type {
	case TypeEC:
		return ecdsa.GenerateKey(opts.Curve, rand.Reader)
	case TypeRSA:
		return rsa.GenerateKey(rand.Reader, opts.Bits)
	default:
		return nil, fmt.Errorf("unsupported key type %q", opts.Type)
	}
}

// EncodePEM PEM-encodes key as PKCS#8, or with legacy set, as SEC1 (EC) or
// PKCS#1 (RSA).
func EncodePEM(key crypto.Signer, legacy bool) ([]byte, error) {
	if !legacy {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	}

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}), nil
	default:
		return nil, fmt.Errorf("no legacy private key format for %T", key)
	}
}
