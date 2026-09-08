package memd

import (
	"errors"
	"net"
	"strconv"
	"testing"
	"time"
)

func startEchoListener(t *testing.T) (addr string, closeFn func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %s", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

// A nil Err is unreachable through DialMemdConn, but DialError is exported: Error() must not panic
func TestDialErrorDoesNotPanicOnNilErr(t *testing.T) {
	e := &DialError{}

	if got := e.Error(); got != "dial failed" {
		t.Errorf("expected a sensible fallback message, got %q", got)
	}

	if got := e.Unwrap(); got != nil {
		t.Errorf("expected Unwrap to still return the nil Err, got %v", got)
	}
}

func TestDialMemdConnTimingNoTLS(t *testing.T) {
	addr, closeFn := startEchoListener(t)
	defer closeFn()

	result, err := DialMemdConn(addr, nil, time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("DialMemdConn failed: %s", err)
	}
	defer result.Conn.Close()

	// Dialing an IP literal performs no lookup, so the phase must stay unstamped rather than report 0s
	if !result.Timing.DNSStart.IsZero() {
		t.Errorf("expected no DNS phase for an IP literal, got %s", result.Timing.DNSStart)
	}
	if result.Timing.TCPDone.Before(result.Timing.TCPStart) {
		t.Errorf("TCPDone (%s) is before TCPStart (%s)", result.Timing.TCPDone, result.Timing.TCPStart)
	}
	if result.Timing.TLS() != 0 {
		t.Errorf("expected zero TLS duration for a non-TLS dial, got %s", result.Timing.TLS())
	}
	if result.TLSState != nil {
		t.Errorf("expected nil TLSState for a non-TLS dial, got %+v", result.TLSState)
	}
}

func TestReadDeadlineBoundsAStalledPeer(t *testing.T) {
	addr, closeFn := startEchoListener(t)
	defer closeFn()

	result, err := DialMemdConn(addr, nil, time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("DialMemdConn failed: %s", err)
	}
	defer result.Conn.Close()

	if err := result.Conn.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline failed: %s", err)
	}

	// The listener never replies, so without a deadline this read would block forever
	var resp Response
	start := time.Now()
	if err := result.Conn.ReadPacket(&resp); err == nil {
		t.Fatal("expected the read to time out")
	}

	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("read took %s, the deadline was not applied", elapsed)
	}
}

// A wildcard resolver answers even this RFC 6761 name, so the tests below skip when it resolves
const unresolvableHost = "this-host-does-not-resolve.invalid"

func requireUnresolvable(t *testing.T) {
	t.Helper()

	if _, err := net.LookupHost(unresolvableHost); err == nil {
		t.Skipf("this resolver answers for %q, so a resolution failure cannot be provoked here",
			unresolvableHost)
	}
}

func TestDialMemdConnUnknownHost(t *testing.T) {
	requireUnresolvable(t)

	_, err := DialMemdConn(unresolvableHost+":11210", nil, time.Now().Add(2*time.Second))
	if err == nil {
		t.Fatal("expected an error dialing an unresolvable host, got nil")
	}
}

func TestDialMemdConnZeroDeadline(t *testing.T) {
	addr, closeFn := startEchoListener(t)
	defer closeFn()

	result, err := DialMemdConn(addr, nil, time.Time{})
	if err != nil {
		t.Fatalf("DialMemdConn with zero deadline failed: %s", err)
	}
	defer result.Conn.Close()
}

func TestAttemptDeadlineSplitsTheTimeLeft(t *testing.T) {
	now := time.Now()

	// Three addresses left, so the first attempt may spend a third of the budget
	if got := attemptDeadline(now.Add(3*time.Second), now, 3); got.Sub(now) != time.Second {
		t.Errorf("expected a 1s slice of a 3s deadline, got %s", got.Sub(now))
	}

	if got := attemptDeadline(now.Add(3*time.Second), now, 1); got.Sub(now) != 3*time.Second {
		t.Errorf("the last attempt should keep the whole deadline, got %s", got.Sub(now))
	}

	if got := attemptDeadline(time.Time{}, now, 3); !got.IsZero() {
		t.Errorf("a zero deadline must stay unbounded, got %s", got)
	}

	passed := now.Add(-time.Second)
	if got := attemptDeadline(passed, now, 3); !got.Equal(passed) {
		t.Errorf("expected the passed deadline back, got %s", got)
	}
}

func TestDialMemdConnUnresolvableHostCarriesDNSDiagnostics(t *testing.T) {
	requireUnresolvable(t)

	result, err := DialMemdConn(unresolvableHost+":11210", nil, time.Now().Add(2*time.Second))
	if err == nil {
		t.Fatal("expected an error dialing an unresolvable host, got nil")
	}

	// The existing contract is preserved: no result on failure
	if result != nil {
		t.Fatalf("expected a nil result on failure, got %+v", result)
	}

	var dialErr *DialError
	if !errors.As(err, &dialErr) {
		t.Fatalf("expected a *DialError, got %T: %s", err, err)
	}

	if dialErr.Timing.DNSStart.IsZero() || dialErr.Timing.DNSDone.IsZero() {
		t.Errorf("expected a stamped DNS phase, got %+v", dialErr.Timing)
	}

	if len(dialErr.Addresses) != 0 {
		t.Errorf("expected no address attempts when resolution failed, got %+v", dialErr.Addresses)
	}

	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		t.Errorf("expected the underlying DNS error to stay unwrappable, got %T", dialErr.Err)
	}
}

func TestDialMemdConnRecordsEveryAddressItTried(t *testing.T) {
	// localhost resolves to every loopback address the host has; a closed port refuses on all of them
	ips, err := net.LookupHost("localhost")
	if err != nil {
		t.Skipf("localhost does not resolve here: %s", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a port: %s", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing is listening on this port now, so every address refuses

	result, err := DialMemdConn(net.JoinHostPort("localhost", strconv.Itoa(port)), nil, time.Now().Add(2*time.Second))
	if err == nil {
		result.Conn.Close()
		t.Fatal("expected the dial to fail against a closed port")
	}

	var dialErr *DialError
	if !errors.As(err, &dialErr) {
		t.Fatalf("expected a *DialError, got %T: %s", err, err)
	}

	if len(dialErr.Addresses) != len(ips) {
		t.Fatalf("expected one record per resolved address (%d), got %d: %+v",
			len(ips), len(dialErr.Addresses), dialErr.Addresses)
	}

	for _, addr := range dialErr.Addresses {
		if addr.Err == nil {
			t.Errorf("expected every address to fail, %s did not", addr.Address)
		}
		if addr.Done.Before(addr.Start) {
			t.Errorf("%s: Done (%s) is before Start (%s)", addr.Address, addr.Done, addr.Start)
		}
	}
}

func TestDialMemdConnRecordsTheAddressThatConnected(t *testing.T) {
	addr, closeFn := startEchoListener(t)
	defer closeFn()

	result, err := DialMemdConn(addr, nil, time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("DialMemdConn failed: %s", err)
	}
	defer result.Conn.Close()

	if len(result.Addresses) != 1 {
		t.Fatalf("expected one address record, got %+v", result.Addresses)
	}

	got := result.Addresses[0]
	if got.Err != nil {
		t.Errorf("expected no error on the connected address, got %s", got.Err)
	}
	if got.Address != addr {
		t.Errorf("expected address %s, got %s", addr, got.Address)
	}
	if got.Local == "" {
		t.Error("expected the local socket address to be recorded")
	}
}

func TestDialMemdConnRecordsTheResolvedAddresses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to read the listener port: %s", err)
	}

	deadline := time.Now().Add(2 * time.Second)

	literal, err := DialMemdConn(net.JoinHostPort("127.0.0.1", port), nil, deadline)
	if err != nil {
		t.Fatalf("dial to the literal failed: %s", err)
	}
	defer literal.Conn.Close()

	if len(literal.Resolved) != 0 {
		t.Errorf("an IP literal reported a resolved set of %v", literal.Resolved)
	}

	named, err := DialMemdConn(net.JoinHostPort("localhost", port), nil, deadline)
	if err != nil {
		t.Skipf("localhost is not usable on this host: %s", err)
	}
	defer named.Conn.Close()

	if len(named.Resolved) == 0 {
		t.Error("a resolved name reported no addresses")
	}
}
