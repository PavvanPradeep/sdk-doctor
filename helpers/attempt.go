package helpers

import (
	"crypto/x509"
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/couchbaselabs/sdk-doctor/memd"
)

// Phase names how far a connection attempt got.  Not every transport uses every
//
//	phase: CCCP has sasl and select-bucket, HTTP has response.
type Phase string

const (
	PhaseNone         Phase = ""
	PhaseDNS          Phase = "dns"
	PhaseTCP          Phase = "tcp"
	PhaseTLS          Phase = "tls"
	PhaseSASL         Phase = "sasl"
	PhaseSelectBucket Phase = "select-bucket"
	PhaseResponse     Phase = "response"
	PhaseConfig       Phase = "config"
)

// Category is a normalized failure cause, stable enough to group tickets by
type Category string

const (
	CategoryDNSNXDomain     Category = "dns_nxdomain"
	CategoryDNSTimeout      Category = "dns_timeout"
	CategoryDNSFailed       Category = "dns_failed"
	CategoryTCPRefused      Category = "tcp_refused"
	CategoryTCPTimeout      Category = "tcp_timeout"
	CategoryTCPUnreachable  Category = "tcp_unreachable"
	CategoryTLSHandshake    Category = "tls_handshake"
	CategoryTLSVerify       Category = "tls_verify"
	CategoryAuthRejected    Category = "authentication_rejected"
	CategoryBucketNotFound  Category = "bucket_not_found"
	CategoryBucketForbidden Category = "bucket_forbidden"
	CategoryCCCPUnsupported Category = "cccp_unsupported"
	CategoryConfigInvalid   Category = "config_invalid"
	CategoryConfigEmpty     Category = "config_empty"
	CategoryServerError     Category = "server_error"
	CategoryUnknown         Category = "unknown"
)

// AllCategories lists every category, so a test can prove each one is reachable
func AllCategories() []Category {
	return []Category{
		CategoryDNSNXDomain, CategoryDNSTimeout, CategoryDNSFailed,
		CategoryTCPRefused, CategoryTCPTimeout, CategoryTCPUnreachable,
		CategoryTLSHandshake, CategoryTLSVerify,
		CategoryAuthRejected, CategoryBucketNotFound, CategoryBucketForbidden,
		CategoryCCCPUnsupported, CategoryConfigInvalid, CategoryConfigEmpty,
		CategoryServerError, CategoryUnknown,
	}
}

// AddressAttempt records one address a connection attempt tried
type AddressAttempt struct {
	Address  string
	Family   string // "ipv4" | "ipv6"
	Local    string `json:",omitempty"`
	Phase    string
	Category string `json:",omitempty"`
	Elapsed  string
	Error    string `json:",omitempty"`
}

// Attempt records one connection attempt against one endpoint, bootstrap or service
type Attempt struct {
	Kind      string
	Endpoint  string
	Resolved  []string         `json:",omitempty"`
	Addresses []AddressAttempt `json:",omitempty"`
	Phase     string
	Category  string `json:",omitempty"`
	Elapsed   string
	Timeout   string
	Error     string `json:",omitempty"`

	DNS  string `json:",omitempty"`
	TCP  string `json:",omitempty"`
	TLS  string `json:",omitempty"`
	SASL string `json:",omitempty"`
}

// Dur formats a duration the way every other field in the report is formatted
func Dur(d time.Duration) string {
	return d.Round(time.Microsecond).String()
}

// Windows reports refusals as WSAECONNREFUSED, which does not match syscall.ECONNREFUSED.
//
//	The Unix numbering is checked too, since syscall defines both sets on Windows.
const (
	wsaeConnRefused    = syscall.Errno(10061)
	wsaeNetUnreachable = syscall.Errno(10051)
	wsaeHostUnreach    = syscall.Errno(10065)
)

// IsConnRefused reports whether the peer answered with a refusal, which proves the
//
//	packets reached it and nothing was listening
func IsConnRefused(err error) bool {
	var errno syscall.Errno

	return errors.As(err, &errno) && (errno == syscall.ECONNREFUSED || errno == wsaeConnRefused)
}

// isUnreachable reports whether the network answered "no route", which is a different
//
//	finding from packets being dropped
func isUnreachable(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}

	return errno == syscall.EHOSTUNREACH || errno == syscall.ENETUNREACH ||
		errno == wsaeHostUnreach || errno == wsaeNetUnreachable
}

func isCertificateError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var invalidCert x509.CertificateInvalidError
	var wrongHostname x509.HostnameError

	return errors.As(err, &unknownAuthority) ||
		errors.As(err, &invalidCert) ||
		errors.As(err, &wrongHostname)
}

// Classify names the cause of err, given the phase it occurred in.  The phase is
//
//	required rather than inferred: a rejected certificate and a broken handshake are
//	indistinguishable from the error alone without matching on its text.
func Classify(phase Phase, err error) Category {
	if err == nil {
		return ""
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return CategoryDNSNXDomain
		case dnsErr.IsTimeout:
			return CategoryDNSTimeout
		default:
			return CategoryDNSFailed
		}
	}

	if phase == PhaseTLS {
		if isCertificateError(err) {
			return CategoryTLSVerify
		}

		return CategoryTLSHandshake
	}

	if IsConnRefused(err) {
		return CategoryTCPRefused
	}

	if isUnreachable(err) {
		return CategoryTCPUnreachable
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return CategoryTCPTimeout
	}

	return CategoryUnknown
}

// CategoryForHTTPStatus maps a non-200 config-fetch response to its cause
func CategoryForHTTPStatus(code int) Category {
	switch {
	case code == 401:
		return CategoryAuthRejected
	case code == 403:
		return CategoryBucketForbidden
	case code == 404:
		return CategoryBucketNotFound
	case code >= 500:
		return CategoryServerError
	default:
		return CategoryUnknown
	}
}

// PhaseOfDial reports the phase a failed dial died in, from the diagnostics it carried
func PhaseOfDial(dialErr *memd.DialError) Phase {
	switch {
	case !dialErr.Timing.TLSStart.IsZero():
		return PhaseTLS
	case len(dialErr.Addresses) > 0:
		return PhaseTCP
	case !dialErr.Timing.DNSStart.IsZero():
		return PhaseDNS
	default:
		return PhaseNone
	}
}
