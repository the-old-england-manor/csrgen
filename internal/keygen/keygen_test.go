package keygen

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

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

func TestParseCurve(t *testing.T) {
	valid := []struct {
		in   string
		want string
	}{
		{"p256", "P-256"},
		{"P-256", "P-256"},
		{"prime256v1", "P-256"},
		{"PRIME256V1", "P-256"},
		{"p384", "P-384"},
		{"p-384", "P-384"},
		{"secp384r1", "P-384"},
		{"P521", "P-521"},
		{"p-521", "P-521"},
		{"secp521r1", "P-521"},
	}
	for _, tc := range valid {
		t.Run(tc.in, func(t *testing.T) {
			curve, err := ParseCurve(tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, curve.Params().Name)
		})
	}

	for _, in := range []string{"", "p224", "secp256k1", "ed25519", "p 256"} {
		t.Run("invalid "+in, func(t *testing.T) {
			_, err := ParseCurve(in)
			assert.Error(t, err)
		})
	}
}

func TestGenerate(t *testing.T) {
	t.Run("EC uses requested curve", func(t *testing.T) {
		key, err := Generate(Options{Type: TypeEC, Curve: elliptic.P384()})
		require.NoError(t, err)
		ecKey, ok := key.(*ecdsa.PrivateKey)
		require.True(t, ok, "expected *ecdsa.PrivateKey, got %T", key)
		assert.Equal(t, "P-384", ecKey.Curve.Params().Name)
	})

	t.Run("RSA uses requested size", func(t *testing.T) {
		key, err := Generate(Options{Type: TypeRSA, Bits: 3072})
		require.NoError(t, err)
		rsaKey, ok := key.(*rsa.PrivateKey)
		require.True(t, ok, "expected *rsa.PrivateKey, got %T", key)
		assert.Equal(t, 3072, rsaKey.N.BitLen())
	})

	t.Run("unknown key type", func(t *testing.T) {
		_, err := Generate(Options{Type: "dsa"})
		assert.Error(t, err)
	})
}

func TestEncodePEM(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("EC PKCS#8", func(t *testing.T) {
		out, err := EncodePEM(ecKey, false)
		require.NoError(t, err)
		block := decodeSinglePEM(t, out)
		assert.Equal(t, "PRIVATE KEY", block.Type)
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)
		assert.True(t, ecKey.Equal(parsed))
	})

	t.Run("RSA PKCS#8", func(t *testing.T) {
		out, err := EncodePEM(rsaKey, false)
		require.NoError(t, err)
		block := decodeSinglePEM(t, out)
		assert.Equal(t, "PRIVATE KEY", block.Type)
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)
		assert.True(t, rsaKey.Equal(parsed))
	})

	t.Run("EC legacy is SEC1", func(t *testing.T) {
		out, err := EncodePEM(ecKey, true)
		require.NoError(t, err)
		block := decodeSinglePEM(t, out)
		assert.Equal(t, "EC PRIVATE KEY", block.Type)
		parsed, err := x509.ParseECPrivateKey(block.Bytes)
		require.NoError(t, err)
		assert.True(t, ecKey.Equal(parsed))
	})

	t.Run("RSA legacy is PKCS#1", func(t *testing.T) {
		out, err := EncodePEM(rsaKey, true)
		require.NoError(t, err)
		block := decodeSinglePEM(t, out)
		assert.Equal(t, "RSA PRIVATE KEY", block.Type)
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		require.NoError(t, err)
		assert.True(t, rsaKey.Equal(parsed))
	})

	t.Run("legacy rejects key types without a legacy format", func(t *testing.T) {
		_, edKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		_, err = EncodePEM(edKey, true)
		assert.Error(t, err)
	})
}
