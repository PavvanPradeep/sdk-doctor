package helpers

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/couchbaselabs/sdk-doctor/memd"
)

// fakeServer answers memcached packets with statuses the test dictates, so auth and
//
//	bucket failures can be provoked without a cluster
type fakeServer struct {
	ln       net.Listener
	statuses map[memd.CommandCode]memd.StatusCode
}

func startFakeServer(t *testing.T, statuses map[memd.CommandCode]memd.StatusCode) (host string, port int, closeFn func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %s", err)
	}

	srv := &fakeServer{ln: ln, statuses: statuses}
	go srv.serve()

	addr := ln.Addr().(*net.TCPAddr)

	return "127.0.0.1", addr.Port, func() { ln.Close() }
}

func (s *fakeServer) serve() {
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	memdConn := memd.NewConn(conn)

	for {
		// memd.ReadWriteCloser is written for the client side of the protocol only
		// (ReadPacket wants a *Response, WritePacket wants a *Request). The request and
		// response headers share the exact same wire layout though (byte 6:8 is "vbucket"
		// on the way in and "status" on the way out), so the server side reads the
		// incoming header into a Response (only .Opcode is needed) and writes its answer
		// as a Request, stashing the status code in the Vbucket field so it lands in the
		// same header bytes a real response would use.
		var req memd.Response
		if err := memdConn.ReadPacket(&req); err != nil {
			return
		}

		resp := memd.Request{
			Magic:   memd.ResMagic,
			Opcode:  req.Opcode,
			Vbucket: uint16(s.statuses[req.Opcode]),
		}

		// SASL_LIST_MECHS must advertise PLAIN or the client stops before authenticating
		if req.Opcode == memd.CmdSASLListMechs {
			resp.Value = []byte("PLAIN")
		}

		if err := memdConn.WritePacket(&resp); err != nil {
			return
		}
	}
}

// startFakeTLSServer is startFakeServer over a TLS listener, using the same self-signed
// cert attempt_testcert_test.go builds for the TLS-classification tests, so a dial with
// InsecureSkipVerify can complete a real handshake against it.
func startFakeTLSServer(t *testing.T, statuses map[memd.CommandCode]memd.StatusCode) (host string, port int, closeFn func()) {
	t.Helper()

	cert, err := selfSignedCert()
	if err != nil {
		t.Fatalf("failed to build a self-signed certificate: %s", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("failed to start TLS listener: %s", err)
	}

	srv := &fakeServer{ln: ln, statuses: statuses}
	go srv.serve()

	addr := ln.Addr().(*net.TCPAddr)

	return "127.0.0.1", addr.Port, func() { ln.Close() }
}

// startDroppingServer accepts one connection, reads exactly one request, then closes
// without answering - so the client's next read fails with a transport error (EOF),
// not a protocol status. This exercises the phase a bare read/write failure occurs in,
// as opposed to the phase a non-zero status is reported for.
func startDroppingServer(t *testing.T) (host string, port int, closeFn func()) {
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

		memdConn := memd.NewConn(conn)
		var req memd.Response
		_ = memdConn.ReadPacket(&req) // read the SASLListMechs request, then drop the connection
	}()

	addr := ln.Addr().(*net.TCPAddr)

	return "127.0.0.1", addr.Port, func() { ln.Close() }
}

func TestDialWrapsATransportFailureInsideAuthWithItsPhase(t *testing.T) {
	host, port, closeFn := startDroppingServer(t)
	defer closeFn()

	client, attempt, err := Dial(host, port, "travel", "Administrator", "password", nil)
	if err == nil {
		client.Close()
		t.Fatal("expected the dial to fail when the peer drops the connection mid-auth")
	}

	var phaseErr *PhaseError
	if !errors.As(err, &phaseErr) {
		t.Fatalf("expected a *PhaseError, got %T: %s", err, err)
	}
	if phaseErr.Phase != PhaseSASL {
		t.Errorf("expected the sasl phase for a transport failure during auth, got %q", phaseErr.Phase)
	}

	if attempt.Phase != string(PhaseSASL) {
		t.Errorf("expected the attempt to record the sasl phase for a transport failure, got %q", attempt.Phase)
	}
}

func TestDialRecordsTLSPhaseForATLSConnectedAddress(t *testing.T) {
	host, port, closeFn := startFakeTLSServer(t, nil)
	defer closeFn()

	client, attempt, err := Dial(host, port, "Administrator", "Administrator", "password",
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("the dial itself should succeed: %s", err)
	}
	defer client.Close()

	if len(attempt.Addresses) == 0 {
		t.Fatalf("expected at least one recorded address, got %+v", attempt)
	}
	// The address connected over TLS, so it reached further than plain TCP - recording
	// it as "tcp" would silently downgrade what actually happened.
	if attempt.Addresses[0].Phase != string(PhaseTLS) {
		t.Errorf("expected the connected address to record the tls phase, got %q", attempt.Addresses[0].Phase)
	}
}

func TestDialReportsAuthRejectionAsAPhaseError(t *testing.T) {
	host, port, closeFn := startFakeServer(t, map[memd.CommandCode]memd.StatusCode{
		memd.CmdSASLAuth: memd.StatusAuthError,
	})
	defer closeFn()

	client, attempt, err := Dial(host, port, "travel", "Administrator", "wrong", nil)
	if err == nil {
		client.Close()
		t.Fatal("expected the dial to fail on a rejected SASL auth")
	}

	var phaseErr *PhaseError
	if !errors.As(err, &phaseErr) {
		t.Fatalf("expected a *PhaseError, got %T: %s", err, err)
	}

	if phaseErr.Phase != PhaseSASL {
		t.Errorf("expected the sasl phase, got %q", phaseErr.Phase)
	}
	if phaseErr.Category != CategoryAuthRejected {
		t.Errorf("expected %q, got %q", CategoryAuthRejected, phaseErr.Category)
	}

	if attempt.Phase != string(PhaseSASL) || attempt.Category != string(CategoryAuthRejected) {
		t.Errorf("expected the attempt to carry the phase and category, got %+v", attempt)
	}
	if attempt.Endpoint == "" || attempt.Elapsed == "" {
		t.Errorf("expected a populated attempt, got %+v", attempt)
	}
	if len(attempt.Addresses) != 1 || attempt.Addresses[0].Error != "" {
		t.Errorf("expected one successfully connected address, got %+v", attempt.Addresses)
	}

	// Resolved should carry the resolved host set, not Addresses[].Address verbatim -
	// each entry must be a bare IP with the port stripped off.
	for _, resolved := range attempt.Resolved {
		if net.ParseIP(resolved) == nil || strings.Contains(resolved, ":") {
			t.Errorf("expected Resolved to hold bare IPs with no port, got %q", resolved)
		}
	}
}

func TestDialReportsBucketNotFound(t *testing.T) {
	host, port, closeFn := startFakeServer(t, map[memd.CommandCode]memd.StatusCode{
		memd.CmdSelectBucket: memd.StatusKeyNotFound,
	})
	defer closeFn()

	client, _, err := Dial(host, port, "nosuchbucket", "Administrator", "password", nil)
	if err == nil {
		client.Close()
		t.Fatal("expected the dial to fail selecting a missing bucket")
	}

	var phaseErr *PhaseError
	if !errors.As(err, &phaseErr) {
		t.Fatalf("expected a *PhaseError, got %T: %s", err, err)
	}

	if phaseErr.Phase != PhaseSelectBucket {
		t.Errorf("expected the select-bucket phase, got %q", phaseErr.Phase)
	}
	if phaseErr.Category != CategoryBucketNotFound {
		t.Errorf("expected %q, got %q", CategoryBucketNotFound, phaseErr.Category)
	}
}

func TestDialReportsCCCPUnsupported(t *testing.T) {
	host, port, closeFn := startFakeServer(t, map[memd.CommandCode]memd.StatusCode{
		memd.CmdGetClusterConfig: memd.StatusUnknownCommand,
	})
	defer closeFn()

	// bucket ("travel") != user ("Administrator"), so selectBucket runs and the
	// successful attempt should report having reached PhaseSelectBucket, the furthest
	// rung this dial actually exercised.
	client, attempt, err := Dial(host, port, "travel", "Administrator", "password", nil)
	if err != nil {
		t.Fatalf("the dial itself should succeed: %s", err)
	}
	defer client.Close()

	if attempt.Phase != string(PhaseSelectBucket) {
		t.Errorf("expected the select-bucket phase on a successful dial that ran selectBucket, got %q", attempt.Phase)
	}
	if len(attempt.Addresses) == 0 {
		t.Errorf("expected the attempt to record the address it connected to, got %+v", attempt)
	}

	_, err = client.GetConfig()
	if err == nil {
		t.Fatal("expected GetConfig to fail")
	}

	var phaseErr *PhaseError
	if !errors.As(err, &phaseErr) {
		t.Fatalf("expected a *PhaseError, got %T: %s", err, err)
	}

	if phaseErr.Category != CategoryCCCPUnsupported {
		t.Errorf("expected %q, got %q", CategoryCCCPUnsupported, phaseErr.Category)
	}
}

func TestDialReportsSASLPhaseWhenSelectBucketIsSkipped(t *testing.T) {
	host, port, closeFn := startFakeServer(t, nil)
	defer closeFn()

	// bucket == user means Dial never calls selectBucket, so the successful attempt
	// must not claim a phase further than sasl - that would report a rung that never ran.
	client, attempt, err := Dial(host, port, "Administrator", "Administrator", "password", nil)
	if err != nil {
		t.Fatalf("the dial itself should succeed: %s", err)
	}
	defer client.Close()

	if attempt.Phase != string(PhaseSASL) {
		t.Errorf("expected the sasl phase when selectBucket is skipped, got %q", attempt.Phase)
	}
}

func TestDialRecordsAFailedConnectAsAnAttempt(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a port: %s", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	client, attempt, err := Dial("127.0.0.1", port, "travel", "Administrator", "password", nil)
	if err == nil {
		client.Close()
		t.Fatal("expected the dial to fail against a closed port")
	}

	if attempt.Phase != string(PhaseTCP) {
		t.Errorf("expected the tcp phase, got %q", attempt.Phase)
	}
	if attempt.Category != string(CategoryTCPRefused) {
		t.Errorf("expected %q, got %q", CategoryTCPRefused, attempt.Category)
	}
	if attempt.Timeout != Dur(2000*time.Millisecond) {
		t.Errorf("expected the dial budget to be recorded, got %q", attempt.Timeout)
	}
}
