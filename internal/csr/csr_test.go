package csr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func TestBuildSANs(t *testing.T) {
	tests := []struct {
		name    string
		cn      string
		extra   []string
		wantDNS []string
		wantIPs []string
	}{
		{
			name:    "CN only",
			cn:      "example.com",
			wantDNS: []string{"example.com"},
			wantIPs: []string{},
		},
		{
			name:    "CN first then extras in order",
			cn:      "example.com",
			extra:   []string{"www.example.com", "api.example.com"},
			wantDNS: []string{"example.com", "www.example.com", "api.example.com"},
			wantIPs: []string{},
		},
		{
			name:    "duplicates dropped",
			cn:      "example.com",
			extra:   []string{"example.com", "www.example.com", "www.example.com"},
			wantDNS: []string{"example.com", "www.example.com"},
			wantIPs: []string{},
		},
		{
			name:    "IPv4 and IPv6 extras become IP SANs",
			cn:      "example.com",
			extra:   []string{"10.0.0.1", "2001:db8::1", "10.0.0.1"},
			wantDNS: []string{"example.com"},
			wantIPs: []string{"10.0.0.1", "2001:db8::1"},
		},
		{
			name:    "IP as CN",
			cn:      "192.168.1.1",
			extra:   []string{"switch.local"},
			wantDNS: []string{"switch.local"},
			wantIPs: []string{"192.168.1.1"},
		},
		{
			name:    "wildcard CN stays a DNS SAN",
			cn:      "*.example.com",
			extra:   []string{"example.com"},
			wantDNS: []string{"*.example.com", "example.com"},
			wantIPs: []string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dns, ips := buildSANs(tc.cn, tc.extra)
			assert.Equal(t, tc.wantDNS, dns)
			assert.Equal(t, tc.wantIPs, ipStrings(ips))
		})
	}
}

func TestBuildSubject(t *testing.T) {
	t.Run("CN only encodes no other attributes", func(t *testing.T) {
		subject := buildSubject(Request{CommonName: "example.com"})
		assert.Equal(t, "CN=example.com", subject.String())
	})

	t.Run("all fields", func(t *testing.T) {
		subject := buildSubject(Request{
			CommonName:         "example.com",
			Organization:       "Example Ltd",
			OrganizationalUnit: "IT Dept",
			Country:            "GB",
			Province:           "England",
			Locality:           "London",
		})
		assert.Equal(t, "example.com", subject.CommonName)
		assert.Equal(t, []string{"Example Ltd"}, subject.Organization)
		assert.Equal(t, []string{"IT Dept"}, subject.OrganizationalUnit)
		assert.Equal(t, []string{"GB"}, subject.Country)
		assert.Equal(t, []string{"England"}, subject.Province)
		assert.Equal(t, []string{"London"}, subject.Locality)
	})
}

func TestCreate(t *testing.T) {
	newEC := func(curve elliptic.Curve) crypto.Signer {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		return k
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keys := []struct {
		name    string
		key     crypto.Signer
		wantAlg x509.SignatureAlgorithm
	}{
		{"EC P-256", newEC(elliptic.P256()), x509.ECDSAWithSHA256},
		{"EC P-384", newEC(elliptic.P384()), x509.ECDSAWithSHA384},
		{"EC P-521", newEC(elliptic.P521()), x509.ECDSAWithSHA512},
		{"RSA 2048", rsaKey, x509.SHA256WithRSA},
	}

	req := Request{
		CommonName:   "example.com",
		Organization: "Example Ltd",
		Country:      "GB",
		SANs:         []string{"www.example.com", "10.0.0.1"},
	}

	for _, tc := range keys {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Create(tc.key, req)
			require.NoError(t, err)

			block, rest := pem.Decode(out)
			require.NotNil(t, block, "no PEM block found")
			assert.Empty(t, rest, "unexpected trailing data after PEM block")
			assert.Equal(t, "CERTIFICATE REQUEST", block.Type)

			parsed, err := x509.ParseCertificateRequest(block.Bytes)
			require.NoError(t, err)
			require.NoError(t, parsed.CheckSignature())

			assert.Equal(t, tc.wantAlg, parsed.SignatureAlgorithm)
			assert.True(t, tc.key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(parsed.PublicKey))
			assert.Equal(t, "example.com", parsed.Subject.CommonName)
			assert.Equal(t, []string{"Example Ltd"}, parsed.Subject.Organization)
			assert.Equal(t, []string{"GB"}, parsed.Subject.Country)
			assert.Equal(t, []string{"example.com", "www.example.com"}, parsed.DNSNames)
			assert.Equal(t, []string{"10.0.0.1"}, ipStrings(parsed.IPAddresses))
		})
	}
}
