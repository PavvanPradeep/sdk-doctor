package helpers

import (
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/couchbaselabs/sdk-doctor/memd"
)

// Phase names how far a connection attempt got; not every transport uses every phase
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
	CategoryResponseTimeout Category = "response_timeout"
	CategoryAuthRejected    Category = "authentication_rejected"
	CategoryBucketNotFound  Category = "bucket_not_found"
	CategoryBucketForbidden Category = "bucket_forbidden"
	CategoryCCCPUnsupported Category = "cccp_unsupported"
	CategoryConfigInvalid   Category = "config_invalid"
	CategoryConfigEmpty     Category = "config_empty"
	// CategoryConfigUnavailable is no configuration at all, as against one that came back empty
	CategoryConfigUnavailable Category = "config_unavailable"
	CategoryServerError       Category = "server_error"
	CategoryHTTPStatus        Category = "http_status"
	CategoryUnknown           Category = "unknown"
)

// AllCategories lists every category, so a test can prove each one is reachable
func AllCategories() []Category {
	return []Category{
		CategoryDNSNXDomain, CategoryDNSTimeout, CategoryDNSFailed,
		CategoryTCPRefused, CategoryTCPTimeout, CategoryTCPUnreachable,
		CategoryTLSHandshake, CategoryTLSVerify, CategoryResponseTimeout,
		CategoryAuthRejected, CategoryBucketNotFound, CategoryBucketForbidden,
		CategoryCCCPUnsupported, CategoryConfigUnavailable, CategoryConfigInvalid, CategoryConfigEmpty,
		CategoryServerError, CategoryHTTPStatus, CategoryUnknown,
	}
}

// AddressAttempt records one address a connection attempt tried
type AddressAttempt struct {
	Address   string
	Family    string // "ipv4" | "ipv6"
	Local     string `json:",omitempty"`
	Interface string `json:",omitempty"`
	Phase     string
	Category  string `json:",omitempty"`
	Elapsed   string
	Error     string `json:",omitempty"`
}

// HTTPProbe records the HTTP portion of a connection attempt
type HTTPProbe struct {
	Path           string
	HealthEndpoint bool   `json:",omitempty"`
	Status         int    `json:",omitempty"`
	Server         string `json:",omitempty"`
	Redirect       string `json:",omitempty"`
	Latency        string `json:",omitempty"`
	Body           string `json:",omitempty"`
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

	HTTP *HTTPProbe `json:",omitempty"`
}

// Dur formats a duration the way every other field in the report is formatted
func Dur(d time.Duration) string {
	return d.Round(time.Microsecond).String()
}

// Windows numbers these errors its own way, and syscall defines both sets there
const (
	wsaeConnRefused    = syscall.Errno(10061)
	wsaeNetUnreachable = syscall.Errno(10051)
	wsaeHostUnreach    = syscall.Errno(10065)
)

// IsConnRefused reports whether the peer refused, which proves the packets reached it
func IsConnRefused(err error) bool {
	var errno syscall.Errno

	return errors.As(err, &errno) && (errno == syscall.ECONNREFUSED || errno == wsaeConnRefused)
}

// isUnreachable reports whether the network answered "no route" rather than dropping packets
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

// Classify names err's cause, using the phase to separate a rejected cert from a broken handshake
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

	// Checked before the TLS split so a stalled handshake reads as a stall, not a failed negotiation
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		switch phase {
		case PhaseTLS, PhaseSASL, PhaseSelectBucket, PhaseResponse, PhaseConfig:
			// These phases only run on an established connection, so this is not a TCP timeout
			return CategoryResponseTimeout
		default:
			return CategoryTCPTimeout
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

// CategoryForServiceHTTPStatus maps a service response without bucket-specific labels
func CategoryForServiceHTTPStatus(code int) Category {
	switch {
	case code == 401:
		return CategoryAuthRejected
	case code >= 500:
		return CategoryServerError
	default:
		return CategoryHTTPStatus
	}
}

// phaseOfDial reports the phase a failed dial died in, from the diagnostics it carried
func phaseOfDial(dialErr *memd.DialError) Phase {
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

// CategoryForMemdStatus maps a memcached status to its category
func CategoryForMemdStatus(status memd.StatusCode) Category {
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

// CategoryForConfigStatus maps a failed config fetch, preferring a named cause over "unsupported"
func CategoryForConfigStatus(status memd.StatusCode) Category {
	// Bucket is already selected here, so KEY_ENOENT means no config came back, not a missing bucket
	if status == memd.StatusKeyNotFound {
		return CategoryConfigUnavailable
	}

	if category := CategoryForMemdStatus(status); category != CategoryUnknown {
		return category
	}

	return CategoryCCCPUnsupported
}

// PhaseError is an error that knows which phase produced it and what it means
type PhaseError struct {
	Phase    Phase
	Category Category
	Err      error
}

// NewPhaseError tags err with the phase and category it belongs to
func NewPhaseError(phase Phase, category Category, err error) *PhaseError {
	return &PhaseError{Phase: phase, Category: category, Err: err}
}

func (e *PhaseError) Error() string {
	if e.Err == nil {
		return string(e.Category)
	}

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
	http      *HTTPProbe

	reached Phase
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

// AddBudget widens the reported timeout for an operation carrying its own deadline
func (b *AttemptBuilder) AddBudget(d time.Duration) *AttemptBuilder {
	b.timeout += d

	return b
}

// withReached records the furthest phase a successful dial exercised, sasl or select-bucket
func (b *AttemptBuilder) withReached(phase Phase) *AttemptBuilder {
	b.reached = phase

	return b
}

// Reached reports the phase withReached recorded; meaningless before Dial has succeeded
func (b *AttemptBuilder) Reached() Phase {
	return b.reached
}

func BareHost(host string) string {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	return host
}

func HostPort(host string, port int) string {
	return net.JoinHostPort(BareHost(host), strconv.Itoa(port))
}

func TLSServerName(host string) string {
	if addr, err := netip.ParseAddr(BareHost(host)); err == nil {
		return addr.WithZone("").String()
	}

	return BareHost(host)
}

func HostIsUsable(host string) bool {
	bare := BareHost(host)

	if _, err := netip.ParseAddr(bare); err == nil {
		return true
	}

	return !strings.ContainsAny(bare, "%\t\n\r ")
}

func interfaceForIP(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		return host[zone+1:]
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var candidate net.IP
			switch typed := addr.(type) {
			case *net.IPNet:
				candidate = typed.IP
			case *net.IPAddr:
				candidate = typed.IP
			}
			if candidate != nil && candidate.Equal(ip) {
				return iface.Name
			}
		}
	}

	return ""
}

func addressFamily(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
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

func (b *AttemptBuilder) WithResolved(addresses []string) *AttemptBuilder {
	b.resolved = addresses

	return b
}

func (b *AttemptBuilder) WithHTTP(probe HTTPProbe) *AttemptBuilder {
	b.http = &probe

	return b
}

func (b *AttemptBuilder) WithAddresses(results []memd.AddressResult, phase Phase) *AttemptBuilder {
	for _, result := range results {
		record := AddressAttempt{
			Address: result.Address,
			Family:  addressFamily(result.Address),
			Local:   result.Local,
			Elapsed: Dur(result.Done.Sub(result.Start)),
			Phase:   string(PhaseTCP),
		}
		if result.Local != "" {
			record.Interface = interfaceForIP(result.Local)
		}

		if result.Err != nil {
			record.Error = result.Err.Error()
			record.Category = string(Classify(PhaseTCP, result.Err))
		} else {
			// The address connected, so it reached at least as far as the attempt did
			record.Phase = string(phase)
		}

		b.addresses = append(b.addresses, record)
	}

	return b
}

// FromDial classifies and seals a failed Dial; err is always non-nil, as Dial seals its own success
func (b *AttemptBuilder) FromDial(err error) Attempt {
	var dialErr *memd.DialError
	if errors.As(err, &dialErr) {
		phase := phaseOfDial(dialErr)
		b.WithTiming(dialErr.Timing, 0).
			WithResolved(dialErr.Resolved).
			WithAddresses(dialErr.Addresses, phase)

		return b.Finish(phase, Classify(phase, err), err)
	}

	// Not a dial failure: a phase error from auth, bucket selection or config
	var phaseErr *PhaseError
	if errors.As(err, &phaseErr) {
		return b.Finish(phaseErr.Phase, phaseErr.Category, err)
	}

	return b.Finish(PhaseNone, CategoryUnknown, err)
}

// Finish seals the record at the given phase and category
func (b *AttemptBuilder) Finish(phase Phase, category Category, err error) Attempt {
	attempt := Attempt{
		Kind:      b.kind,
		Endpoint:  b.endpoint,
		Resolved:  b.resolved,
		Addresses: b.addresses,
		HTTP:      b.http,
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
