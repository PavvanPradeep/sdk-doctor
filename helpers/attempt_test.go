package helpers

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"
	"testing"
	"time"
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

// provokeNXDomain returns the real error for a name that cannot resolve
func provokeNXDomain(t *testing.T) error {
	t.Helper()

	_, err := net.LookupHost("this-host-does-not-resolve.invalid")
	if err == nil {
		t.Fatal("expected a resolution failure for a .invalid name")
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

		// Accept does not itself perform the handshake (it is deferred to the first
		//  Read/Write), so drive it explicitly: only then does the server actually send
		//  its certificate for the client to reject.
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

func TestClassifyDistinguishesHandshakeFromVerification(t *testing.T) {
	// A TLS-phase failure that is not a certificate problem is a handshake problem
	generic := &net.OpError{Op: "remote error", Err: errTestHandshake{}}

	if got := Classify(PhaseTLS, generic); got != CategoryTLSHandshake {
		t.Errorf("expected a handshake category for a non-x509 TLS error, got %q", got)
	}

	if got := Classify(PhaseTLS, x509.UnknownAuthorityError{}); got != CategoryTLSVerify {
		t.Errorf("expected a verification category for an x509 error, got %q", got)
	}
}

type errTestHandshake struct{}

func (errTestHandshake) Error() string { return "handshake failure" }

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

func TestClassifyReturnsNoCategoryForSuccess(t *testing.T) {
	if got := Classify(PhaseConfig, nil); got != "" {
		t.Errorf("expected an empty category for a nil error, got %q", got)
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
