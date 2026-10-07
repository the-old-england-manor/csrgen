package check

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exampleCert is a throwaway self-signed leaf certificate (CN=example.com,
// CA:FALSE). Its private key was destroyed right after signing, so no key is
// stored here. exampleSHA256 is what openssl reports for it:
//
//	openssl x509 -in example.crt -noout -pubkey | openssl sha256
const exampleCert = `-----BEGIN CERTIFICATE-----
MIIBmDCCAT6gAwIBAgIUXZ2C7w4sXPzlZB1WBU1+LVzCvlcwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wIBcNMjYxMDA3MDExMTIxWhgPMjEyNjA5
MTMwMTExMjFaMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEB3f20pg+vy5H5nBUNGLH2kkZMqSARb5+6EaSk0tlVaRtO85W
whwt/sDs8+mbGgqU5FFnazsbo+aUCsscIaGrgaNoMGYwHQYDVR0OBBYEFGc0W1qa
Mh+v1v6ZhtNt7eMvHgNKMB8GA1UdIwQYMBaAFGc0W1qaMh+v1v6ZhtNt7eMvHgNK
MAwGA1UdEwEB/wQCMAAwFgYDVR0RBA8wDYILZXhhbXBsZS5jb20wCgYIKoZIzj0E
AwIDSAAwRQIgPaGE8wvbnjTI5g+YpdxJsd9sxmkj+8S24P2PgwaG6xsCIQCsPMGR
RAewxSwEEJuOnf9NSAgeWuDKju/rPQSwYxxAfQ==
-----END CERTIFICATE-----
`

const exampleSHA256 = "56edaef931620d95b09ddb7d7119e12427150ad58318a4f2666059dde10268dc"

func selfSignedCertPEM(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pkcs8PEM(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func sec1PEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func TestFromCertificate(t *testing.T) {
	want := KeyInfo{Type: "ECDSA P-256", SHA256: exampleSHA256}
	otherKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	t.Run("PEM matches openssl fingerprint", func(t *testing.T) {
		got, err := FromCertificate([]byte(exampleCert))
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("DER", func(t *testing.T) {
		block, _ := pem.Decode([]byte(exampleCert))
		require.NotNil(t, block)
		got, err := FromCertificate(block.Bytes)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("chain uses the first certificate", func(t *testing.T) {
		chain := append([]byte(exampleCert), selfSignedCertPEM(t, otherKey)...)
		got, err := FromCertificate(chain)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("skips non-certificate blocks", func(t *testing.T) {
		bundle := append(pkcs8PEM(t, otherKey), []byte(exampleCert)...)
		got, err := FromCertificate(bundle)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	invalid := map[string][]byte{
		"empty":       nil,
		"garbage":     []byte("not a certificate"),
		"key only":    pkcs8PEM(t, otherKey),
		"corrupt PEM": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}),
		"corrupt DER": {0x30, 0x03, 0x02, 0x01},
	}
	for name, data := range invalid {
		t.Run("invalid: "+name, func(t *testing.T) {
			_, err := FromCertificate(data)
			assert.Error(t, err)
		})
	}
}

func TestFromPrivateKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	fromCert, err := FromCertificate(selfSignedCertPEM(t, ecKey))
	require.NoError(t, err)

	t.Run("PKCS#8 matches the certificate for the same key", func(t *testing.T) {
		got, err := FromPrivateKey(pkcs8PEM(t, ecKey))
		require.NoError(t, err)
		assert.Equal(t, "ECDSA P-256", got.Type)
		assert.Equal(t, fromCert, got)
	})

	t.Run("SEC1 gives the same fingerprint", func(t *testing.T) {
		got, err := FromPrivateKey(sec1PEM(t, ecKey))
		require.NoError(t, err)
		assert.Equal(t, fromCert, got)
	})

	t.Run("EC PARAMETERS block before the key is skipped", func(t *testing.T) {
		params := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}})
		got, err := FromPrivateKey(append(params, sec1PEM(t, ecKey)...))
		require.NoError(t, err)
		assert.Equal(t, fromCert, got)
	})

	t.Run("RSA PKCS#1 and PKCS#8 agree", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		fromPKCS1, err := FromPrivateKey(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))
		require.NoError(t, err)
		fromPKCS8, err := FromPrivateKey(pkcs8PEM(t, rsaKey))
		require.NoError(t, err)

		assert.Equal(t, "RSA 2048", fromPKCS1.Type)
		assert.Equal(t, fromPKCS1, fromPKCS8)
		assert.Len(t, fromPKCS1.SHA256, 64)
	})

	t.Run("encrypted PKCS#8 is rejected", func(t *testing.T) {
		data := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("whatever")})
		_, err := FromPrivateKey(data)
		assert.ErrorContains(t, err, "encrypted")
	})

	t.Run("legacy encrypted PEM is rejected", func(t *testing.T) {
		data := pem.EncodeToMemory(&pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00"},
			Bytes:   []byte("whatever"),
		})
		_, err := FromPrivateKey(data)
		assert.ErrorContains(t, err, "encrypted")
	})

	invalid := map[string][]byte{
		"empty":            nil,
		"garbage":          []byte("not a key"),
		"certificate only": []byte(exampleCert),
		"corrupt key":      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")}),
	}
	for name, data := range invalid {
		t.Run("invalid: "+name, func(t *testing.T) {
			_, err := FromPrivateKey(data)
			assert.Error(t, err)
		})
	}
}

func TestCertificateMatchesItsKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert, err := FromCertificate(selfSignedCertPEM(t, rsaKey))
	require.NoError(t, err)
	key, err := FromPrivateKey(pkcs8PEM(t, rsaKey))
	require.NoError(t, err)

	assert.NoError(t, Match(cert, key))
}

func TestKeyType(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	assert.Equal(t, "ECDSA P-384", keyType(&p384.PublicKey))
	assert.Equal(t, "RSA 2048", keyType(&rsaKey.PublicKey))
	assert.Equal(t, "Ed25519", keyType(edPub))
}

func TestMatch(t *testing.T) {
	ec1 := KeyInfo{Type: "ECDSA P-256", SHA256: "aaaa"}
	ec2 := KeyInfo{Type: "ECDSA P-256", SHA256: "bbbb"}
	rsa1 := KeyInfo{Type: "RSA 2048", SHA256: "cccc"}

	t.Run("same key", func(t *testing.T) {
		assert.NoError(t, Match(ec1, ec1))
	})

	t.Run("same type, different key", func(t *testing.T) {
		assert.ErrorIs(t, Match(ec1, ec2), ErrMismatch)
	})

	t.Run("different key types are named", func(t *testing.T) {
		err := Match(rsa1, ec1)
		assert.ErrorIs(t, err, ErrMismatch)
		assert.ErrorContains(t, err, "RSA 2048")
		assert.ErrorContains(t, err, "ECDSA P-256")
	})
}
