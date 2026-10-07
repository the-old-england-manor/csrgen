// Package csr builds PEM-encoded certificate signing requests.
package csr

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
)

// Request describes the CSR to create. Empty subject fields are left out.
// The common name is always included as the first SAN; SANs lists any
// additional names, and values that parse as IP addresses become IP SANs.
type Request struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
	SANs               []string
}

// Create returns a PEM-encoded CSR for req, signed by key. The signature
// algorithm is left to Go's default for the key type and size.
func Create(key crypto.Signer, req Request) ([]byte, error) {
	dns, ips := buildSANs(req.CommonName, req.SANs)
	template := &x509.CertificateRequest{
		Subject:     buildSubject(req),
		DNSNames:    dns,
		IPAddresses: ips,
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// buildSANs returns the CN followed by extra, with exact duplicates dropped,
// split into DNS names and IP addresses.
func buildSANs(cn string, extra []string) ([]string, []net.IP) {
	dns := []string{}
	ips := []net.IP{}
	seen := make(map[string]bool)

	for _, name := range append([]string{cn}, extra...) {
		if seen[name] {
			continue
		}
		seen[name] = true

		ip := net.ParseIP(name)
		if ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, name)
		}
	}
	return dns, ips
}

// buildSubject sets each optional subject attribute only when it is non-empty,
// so no empty RDNs end up in the CSR.
func buildSubject(req Request) pkix.Name {
	subject := pkix.Name{CommonName: req.CommonName}
	if req.Organization != "" {
		subject.Organization = []string{req.Organization}
	}
	if req.OrganizationalUnit != "" {
		subject.OrganizationalUnit = []string{req.OrganizationalUnit}
	}
	if req.Country != "" {
		subject.Country = []string{req.Country}
	}
	if req.Province != "" {
		subject.Province = []string{req.Province}
	}
	if req.Locality != "" {
		subject.Locality = []string{req.Locality}
	}
	return subject
}
