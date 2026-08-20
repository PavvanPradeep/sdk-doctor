package helpers

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

// TLSCertInfo describes one certificate in a negotiated TLS chain.
type TLSCertInfo struct {
	Subject      string
	Issuer       string
	NotAfter     time.Time
	DaysToExpiry int
}

// TLSChainInfo describes a completed TLS handshake: negotiated protocol
// version and cipher, the full certificate chain, and whether the hostname
// that was dialed is covered by the leaf certificate's SANs.
type TLSChainInfo struct {
	VersionName string
	CipherName  string
	Chain       []TLSCertInfo
	HostMatches bool
	DialedHost  string
	LeafSANs    []string
}

// BuildTLSChainInfo extracts diagnostic information from a completed TLS
// handshake's connection state. now is passed explicitly so expiry
// calculations are deterministic to call and to test.
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

// daysToExpiry returns how many whole days remain until notAfter, relative
// to now. Negative values mean the certificate has already expired.
func daysToExpiry(notAfter, now time.Time) int {
	return int(notAfter.Sub(now).Hours() / 24)
}

// certificateMatchesHost reports whether host is covered by cert's subject
// alternative names.
func certificateMatchesHost(cert *x509.Certificate, host string) bool {
	return cert.VerifyHostname(host) == nil
}
