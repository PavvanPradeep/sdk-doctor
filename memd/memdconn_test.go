package memd

import (
	"net"
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

func TestDialMemdConnUnknownHost(t *testing.T) {
	_, err := DialMemdConn("this-host-does-not-resolve.invalid:11210", nil, time.Now().Add(2*time.Second))
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
