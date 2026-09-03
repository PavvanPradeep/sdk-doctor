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

// CategoriesFromMemdStatus maps a memcached status to its category, exported so a
//
//	coverage test can prove each one is produced by real code
func CategoriesFromMemdStatus(status memd.StatusCode) Category {
	switch status {
	case memd.StatusAuthError:
		return CategoryAuthRejected
	case memd.StatusKeyNotFound:
		return CategoryBucketNotFound
	case memd.StatusAccessError:
		return CategoryBucketForbidden
	default:
		return CategoryUnknown
	}
}

// PhaseError is an error that knows which phase produced it and what it means
type PhaseError struct {
	Phase    Phase
	Category Category
	Err      error
}

// NewPhaseError builds a PhaseError, tagging err with the phase and category it belongs to
func NewPhaseError(phase Phase, category Category, err error) *PhaseError {
	return &PhaseError{Phase: phase, Category: category, Err: err}
}

func (e *PhaseError) Error() string {
	return e.Err.Error()
}

func (e *PhaseError) Unwrap() error {
	return e.Err
}

// AttemptBuilder accumulates one attempt's record as the attempt proceeds
type AttemptBuilder struct {
	kind     string
	endpoint string
	timeout  time.Duration
	start    time.Time

	timing memd.ConnectTiming
	sasl   time.Duration

	resolved  []string
	addresses []AddressAttempt
}

// NewAttempt starts recording an attempt against endpoint, stamping the start time
func NewAttempt(kind, endpoint string, timeout time.Duration) *AttemptBuilder {
	return &AttemptBuilder{
		kind:     kind,
		endpoint: endpoint,
		timeout:  timeout,
		start:    time.Now(),
	}
}

// WithTiming records per-phase durations, whether the attempt went on to succeed or fail
func (b *AttemptBuilder) WithTiming(timing memd.ConnectTiming, sasl time.Duration) *AttemptBuilder {
	b.timing = timing
	b.sasl = sasl

	return b
}

// resolvedHost strips the port off address, so Resolved carries the resolved host set
// rather than duplicating Addresses[].Address verbatim
func resolvedHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}

	return host
}

func addressFamily(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}

	ip := net.ParseIP(host)
	switch {
	case ip == nil:
		return ""
	case ip.To4() != nil:
		return "ipv4"
	default:
		return "ipv6"
	}
}

// withAddresses converts memd's raw per-address results into report records
func (b *AttemptBuilder) withAddresses(results []memd.AddressResult, phase Phase) *AttemptBuilder {
	for _, result := range results {
		record := AddressAttempt{
			Address: result.Address,
			Family:  addressFamily(result.Address),
			Local:   result.Local,
			Elapsed: Dur(result.Done.Sub(result.Start)),
			Phase:   string(PhaseTCP),
		}

		if result.Err != nil {
			record.Error = result.Err.Error()
			record.Category = string(Classify(PhaseTCP, result.Err))
		} else {
			// The address connected, so it reached at least as far as the attempt did
			record.Phase = string(phase)
		}

		b.addresses = append(b.addresses, record)
		b.resolved = append(b.resolved, resolvedHost(result.Address))
	}

	return b
}

// FromDial records the outcome of a memd dial, successful or not
func (b *AttemptBuilder) FromDial(result *memd.DialResult, err error) Attempt {
	if err == nil {
		b.WithTiming(result.Timing, 0).withAddresses(result.Addresses, PhaseTCP)

		return b.Finish(PhaseTCP, "", nil)
	}

	var dialErr *memd.DialError
	if errors.As(err, &dialErr) {
		phase := PhaseOfDial(dialErr)
		b.WithTiming(dialErr.Timing, 0).withAddresses(dialErr.Addresses, phase)

		return b.Finish(phase, Classify(phase, err), err)
	}

	// Not a dial failure: a phase error from auth, bucket selection or config
	var phaseErr *PhaseError
	if errors.As(err, &phaseErr) {
		return b.Finish(phaseErr.Phase, phaseErr.Category, err)
	}

	return b.Finish(PhaseNone, CategoryUnknown, err)
}

// RestampAttempt moves a completed attempt's outcome to a later phase, for failures that
//
//	happen after Dial has already returned its record.  start must be the time the overall
//	attempt began (before Dial was called), so Elapsed is recomputed to cover the whole
//	attempt rather than staying frozen at whatever Dial's own Finish measured.
func RestampAttempt(attempt Attempt, phase Phase, err error, start time.Time) Attempt {
	attempt.Phase = string(phase)
	attempt.Error = err.Error()
	attempt.Elapsed = Dur(time.Since(start))

	var phaseErr *PhaseError
	if errors.As(err, &phaseErr) {
		attempt.Phase = string(phaseErr.Phase)
		attempt.Category = string(phaseErr.Category)

		return attempt
	}

	attempt.Category = string(Classify(phase, err))

	return attempt
}

// Finish seals the record at the given phase and category
func (b *AttemptBuilder) Finish(phase Phase, category Category, err error) Attempt {
	attempt := Attempt{
		Kind:      b.kind,
		Endpoint:  b.endpoint,
		Resolved:  b.resolved,
		Addresses: b.addresses,
		Phase:     string(phase),
		Category:  string(category),
		Elapsed:   Dur(time.Since(b.start)),
		Timeout:   Dur(b.timeout),
	}

	if err != nil {
		attempt.Error = err.Error()
	}

	if !b.timing.DNSStart.IsZero() {
		attempt.DNS = Dur(b.timing.DNS())
	}
	if !b.timing.TCPStart.IsZero() {
		attempt.TCP = Dur(b.timing.TCP())
	}
	if !b.timing.TLSStart.IsZero() {
		attempt.TLS = Dur(b.timing.TLS())
	}
	if b.sasl > 0 {
		attempt.SASL = Dur(b.sasl)
	}

	return attempt
}
