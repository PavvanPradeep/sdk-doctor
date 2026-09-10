package helpers

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/couchbaselabs/sdk-doctor/memd"
)

// provokeRefused returns the real error the platform produces for a closed port
func provokeRefused(t *testing.T) error {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a port: %s", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("expected a refusal from a closed port")
	}

	return err
}

// provokeNXDomain returns the real error for a name that cannot resolve, skipping if it does
func provokeNXDomain(t *testing.T) error {
	t.Helper()

	_, err := net.LookupHost("this-host-does-not-resolve.invalid")
	if err == nil {
		t.Skip("this resolver answers for a .invalid name, so a lookup failure cannot be provoked here")
	}

	return err
}

// provokeTimeout returns the real error for a dial that outlives its deadline
func provokeTimeout(t *testing.T) error {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %s", err)
	}
	defer ln.Close()

	d := net.Dialer{Timeout: time.Nanosecond}
	conn, err := d.Dial("tcp", ln.Addr().String())
	if err == nil {
		conn.Close()
		t.Skip("a 1ns dial completed on this host; cannot provoke a timeout")
	}

	return err
}

// provokeTLSVerify returns the real x509 error for an untrusted self-signed certificate
func provokeTLSVerify(t *testing.T) error {
	t.Helper()

	cert, err := selfSignedCert()
	if err != nil {
		t.Fatalf("failed to build a test certificate: %s", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("failed to start a TLS listener: %s", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Accept defers the handshake to the first Read/Write, so drive it explicitly here
		if tlsConn, ok := conn.(*tls.Conn); ok {
			tlsConn.Handshake()
		}
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "localhost"})
	if err == nil {
		conn.Close()
		t.Fatal("expected the self-signed certificate to be rejected")
	}

	return err
}

func TestClassifyProvokedNetworkErrors(t *testing.T) {
	tests := []struct {
		name    string
		phase   Phase
		provoke func(*testing.T) error
		want    Category
	}{
		{"refused port", PhaseTCP, provokeRefused, CategoryTCPRefused},
		{"unresolvable name", PhaseDNS, provokeNXDomain, CategoryDNSNXDomain},
		{"dial timeout", PhaseTCP, provokeTimeout, CategoryTCPTimeout},
		{"untrusted certificate", PhaseTLS, provokeTLSVerify, CategoryTLSVerify},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.provoke(t)

			if got := Classify(test.phase, err); got != test.want {
				t.Errorf("Classify(%q, %v) = %q, want %q", test.phase, err, got, test.want)
			}
		})
	}
}

// Telling "the peer said no" from "the peer was never reached" separates refused from unreachable
func TestIsConnRefused(t *testing.T) {
	if refused := provokeRefused(t); !IsConnRefused(refused) {
		t.Errorf("expected a refusal to be recognised, got %v", refused)
	}

	if nxdomain := provokeNXDomain(t); IsConnRefused(nxdomain) {
		t.Errorf("expected a lookup failure to not be a refusal, got %v", nxdomain)
	}

	if IsConnRefused(errors.New("invalid bucket name/password")) {
		t.Error("an auth rejection carries no errno, so it cannot be a refusal")
	}
}

// A TLS-phase failure is a handshake problem unless it's specifically a certificate problem
func TestClassifyDistinguishesHandshakeFromVerification(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want Category
	}{
		{"wrapped generic error", &net.OpError{Op: "remote error", Err: errTestHandshake{}}, CategoryTLSHandshake},
		{"record header error", tls.RecordHeaderError{Msg: "not a handshake"}, CategoryTLSHandshake},
		{"unknown authority", x509.UnknownAuthorityError{}, CategoryTLSVerify},
	}

	for _, test := range tests {
		if got := Classify(PhaseTLS, test.err); got != test.want {
			t.Errorf("%s: Classify(tls, %v) = %q, want %q", test.name, test.err, got, test.want)
		}
	}
}

type errTestHandshake struct{}

func (errTestHandshake) Error() string { return "handshake failure" }

// Only the phase knows whether the connection was established, so "sasl / tcp_timeout" is a contradiction
func TestClassifyTimeoutsAreNamedByPhase(t *testing.T) {
	tests := []struct {
		phase Phase
		want  Category
	}{
		{PhaseNone, CategoryTCPTimeout},
		{PhaseTCP, CategoryTCPTimeout},
		// TLS runs on an established connection, so a stall is the peer going quiet
		{PhaseTLS, CategoryResponseTimeout},
		{PhaseSASL, CategoryResponseTimeout},
		{PhaseSelectBucket, CategoryResponseTimeout},
		{PhaseResponse, CategoryResponseTimeout},
		{PhaseConfig, CategoryResponseTimeout},
	}

	for _, test := range tests {
		if got := Classify(test.phase, errTestTimeout{}); got != test.want {
			t.Errorf("Classify(%q, timeout) = %q, want %q", test.phase, got, test.want)
		}
	}
}

type errTestTimeout struct{}

func (errTestTimeout) Error() string   { return "i/o timeout" }
func (errTestTimeout) Timeout() bool   { return true }
func (errTestTimeout) Temporary() bool { return true }

// "CCCP is not supported" for a permission error sends the reader hunting an old server
func TestCategoryForConfigStatusKeepsMeaningfulStatuses(t *testing.T) {
	tests := []struct {
		status memd.StatusCode
		want   Category
	}{
		{memd.StatusUnknownCommand, CategoryCCCPUnsupported},
		{memd.StatusNotSupported, CategoryCCCPUnsupported},
		{memd.StatusAccessError, CategoryBucketForbidden},
		{memd.StatusAuthError, CategoryAuthRejected},
		// bucket is already selected here, so KEY_ENOENT means no config came back, not a missing bucket
		{memd.StatusKeyNotFound, CategoryConfigUnavailable},
	}

	for _, test := range tests {
		if got := CategoryForConfigStatus(test.status); got != test.want {
			t.Errorf("CategoryForConfigStatus(%#x) = %q, want %q", test.status, got, test.want)
		}
	}
}

func TestClassifyDNSVariants(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want Category
	}{
		{"not found", &net.DNSError{Err: "no such host", IsNotFound: true}, CategoryDNSNXDomain},
		{"timeout", &net.DNSError{Err: "timeout", IsTimeout: true}, CategoryDNSTimeout},
		{"other", &net.DNSError{Err: "server misbehaving"}, CategoryDNSFailed},
	}

	for _, test := range tests {
		if got := Classify(PhaseDNS, test.err); got != test.want {
			t.Errorf("%s: got %q, want %q", test.name, got, test.want)
		}
	}
}

func TestCategoryForHTTPStatus(t *testing.T) {
	tests := []struct {
		code int
		want Category
	}{
		{401, CategoryAuthRejected},
		{403, CategoryBucketForbidden},
		{404, CategoryBucketNotFound},
		{500, CategoryServerError},
		{503, CategoryServerError},
		{418, CategoryUnknown},
	}

	for _, test := range tests {
		if got := CategoryForHTTPStatus(test.code); got != test.want {
			t.Errorf("CategoryForHTTPStatus(%d) = %q, want %q", test.code, got, test.want)
		}
	}
}

func TestCategoryForServiceHTTPStatus(t *testing.T) {
	tests := []struct {
		code int
		want Category
	}{
		{401, CategoryAuthRejected},
		{403, CategoryHTTPStatus},
		{404, CategoryHTTPStatus},
		{503, CategoryServerError},
	}

	for _, test := range tests {
		if got := CategoryForServiceHTTPStatus(test.code); got != test.want {
			t.Errorf("CategoryForServiceHTTPStatus(%d) = %q, want %q", test.code, got, test.want)
		}
	}
}

func TestClassifyReturnsNoCategoryForSuccess(t *testing.T) {
	if got := Classify(PhaseConfig, nil); got != "" {
		t.Errorf("expected an empty category for a nil error, got %q", got)
	}
}

// A nil Err is unreachable through NewPhaseError, but PhaseError is exported: Error() must not panic
func TestPhaseErrorDoesNotPanicOnNilErr(t *testing.T) {
	e := &PhaseError{Phase: PhaseTLS, Category: CategoryTLSVerify}

	if got := e.Error(); got != string(CategoryTLSVerify) {
		t.Errorf("expected the category as a fallback message, got %q", got)
	}

	if got := e.Unwrap(); got != nil {
		t.Errorf("expected Unwrap to still return the nil Err, got %v", got)
	}
}

func TestDurMatchesTheReportFormat(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		// Sub-microsecond precision is deliberately discarded, rounding away from zero
		{1500 * time.Nanosecond, "2µs"},
		{1234567 * time.Nanosecond, "1.235ms"},
		{2 * time.Millisecond, "2ms"},
	}

	for _, test := range tests {
		if got := Dur(test.in); got != test.want {
			t.Errorf("Dur(%d) = %q, want %q", test.in, got, test.want)
		}
	}
}

// The select-bucket path keeps the other meaning of KEY_ENOENT, where the bucket really is missing
func TestCategoryForMemdStatusStillReadsKeyNotFoundAsAMissingBucket(t *testing.T) {
	if got := CategoryForMemdStatus(memd.StatusKeyNotFound); got != CategoryBucketNotFound {
		t.Errorf("CategoryForMemdStatus(KeyNotFound) = %q, want %q", got, CategoryBucketNotFound)
	}
}

// GetConfig adds its own timeout after the dial deadline clears, so the budget must grow
func TestAttemptBuilderAddBudgetExtendsTheReportedTimeout(t *testing.T) {
	builder := NewAttempt("bootstrap-cccp", "node1:11210", 2000*time.Millisecond)

	builder.AddBudget(OpTimeout)

	got := builder.Finish(PhaseConfig, "", nil).Timeout
	if got != "4s" {
		t.Errorf("Timeout = %q, want %q", got, "4s")
	}
}

// Without the extension the record claims a 2s bound for work that may legitimately take longer
func TestDialStartsTheAttemptAtTheDialBudget(t *testing.T) {
	host, port, closeFn := startFakeServer(t, nil)
	defer closeFn()

	_, builder, err := Dial("bootstrap-cccp", host, port, "travel", "Administrator", "password", nil)
	if err != nil {
		t.Fatalf("Dial failed: %s", err)
	}

	if got := builder.Finish(PhaseSASL, "", nil).Timeout; got != "2s" {
		t.Errorf("Timeout = %q, want the dial budget %q", got, "2s")
	}
}

func TestInterfaceForIP(t *testing.T) {
	loopback := interfaceForIP("127.0.0.1:53182")
	if loopback == "" {
		t.Skip("this host exposes no interface holding 127.0.0.1")
	}

	if got := interfaceForIP("127.0.0.1"); got != loopback {
		t.Errorf("a bare address resolved to %q, want the same interface %q", got, loopback)
	}
	if got := interfaceForIP("[fe80::1%en0]:53182"); got != "en0" {
		t.Errorf("a zoned address resolved to %q, want %q", got, "en0")
	}
	if got := addressFamily("[fe80::1%en0]:53182"); got != "ipv6" {
		t.Errorf("a zoned address family is %q, want %q", got, "ipv6")
	}

	for _, unknown := range []string{"", "203.0.113.1:11210", "not-an-address"} {
		if got := interfaceForIP(unknown); got != "" {
			t.Errorf("interfaceForIP(%q) = %q, want no interface", unknown, got)
		}
	}
}
