package helpers

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestDaysToExpiry(t *testing.T) {
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		notAfter time.Time
		want     int
	}{
		{"19 days out", now.Add(19 * 24 * time.Hour), 19},
		{"already expired", now.Add(-5 * 24 * time.Hour), -5},
		{"expires now", now, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := daysToExpiry(tc.notAfter, now)
			if got != tc.want {
				t.Errorf("daysToExpiry(%s, %s) = %d, want %d", tc.notAfter, now, got, tc.want)
			}
		})
	}
}

func TestCertificateMatchesHost(t *testing.T) {
	tests := []struct {
		name     string
		dnsNames []string
		host     string
		want     bool
	}{
		{"exact match", []string{"node1.prod.internal"}, "node1.prod.internal", true},
		{"wildcard match", []string{"*.prod.internal"}, "node2.prod.internal", true},
		{"mismatch", []string{"*.prod.internal"}, "node2.other.internal", false},
		{"no SANs", nil, "node1.prod.internal", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{
				Subject:  pkix.Name{CommonName: "placeholder"},
				DNSNames: tc.dnsNames,
			}

			got := certificateMatchesHost(cert, tc.host)
			if got != tc.want {
				t.Errorf("certificateMatchesHost(DNSNames=%v, %q) = %v, want %v", tc.dnsNames, tc.host, got, tc.want)
			}
		})
	}
}

func TestBuildTLSChainInfoNoCertificates(t *testing.T) {
	state := tls.ConnectionState{}
	info := BuildTLSChainInfo(&state, "node1.prod.internal", time.Now())
	if len(info.Chain) != 0 {
		t.Errorf("expected empty chain, got %d entries", len(info.Chain))
	}
	if info.HostMatches {
		t.Errorf("expected HostMatches to be false with no certificates presented")
	}
}
