package helpers

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

// TLSCertInfo describes one certificate in a TLS chain
type TLSCertInfo struct {
	Subject      string
	Issuer       string
	NotAfter     time.Time
	DaysToExpiry int
}

// TLSChainInfo describes a handshake: version, cipher, chain and host match
type TLSChainInfo struct {
	VersionName string
	CipherName  string
	Chain       []TLSCertInfo
	HostMatches bool
	DialedHost  string
	LeafSANs    []string
}

// BuildTLSChainInfo extracts diagnostics from a completed handshake
func BuildTLSChainInfo(state *tls.ConnectionState, dialedHost string, now time.Time) TLSChainInfo {
	info := TLSChainInfo{
		VersionName: tlsVersionName(state.Version),
		CipherName:  tls.CipherSuiteName(state.CipherSuite),
		DialedHost:  dialedHost,
	}

	for _, cert := range state.PeerCertificates {
		info.Chain = append(info.Chain, TLSCertInfo{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			NotAfter:     cert.NotAfter,
			DaysToExpiry: daysToExpiry(cert.NotAfter, now),
		})
	}

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		info.LeafSANs = leaf.DNSNames
		info.HostMatches = certificateMatchesHost(leaf, dialedHost)
	}

	return info
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}

func daysToExpiry(notAfter, now time.Time) int {
	return int(notAfter.Sub(now).Hours() / 24)
}

func certificateMatchesHost(cert *x509.Certificate, host string) bool {
	return cert.VerifyHostname(host) == nil
}
