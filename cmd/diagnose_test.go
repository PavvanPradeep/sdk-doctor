package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/couchbaselabs/sdk-doctor/helpers"
	"github.com/couchbaselabs/sdk-doctor/memd"
)

func TestGetSourceNodeExt(t *testing.T) {
	none := terseBucketConfig{NodesExt: []bucketConfigNodeExt{
		{Hostname: "a"}, {Hostname: "b"},
	}}
	if got := none.GetSourceNodeExt(); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}

	some := terseBucketConfig{NodesExt: []bucketConfigNodeExt{
		{Hostname: "a"}, {Hostname: "b", ThisNode: true},
	}}
	if got := some.GetSourceNodeExt(); got == nil || got.Hostname != "b" {
		t.Fatalf("expected node b, got %+v", got)
	}
}

func TestMatrixPorts(t *testing.T) {
	nodes := []clusterNode{
		{Hostname: "a", Services: map[string]int{"indexAdmin": 9100, "kv": 11210, "kvSSL": 11207}},
		{Hostname: "b", Services: map[string]int{"projector": 9999, "capi": 0}},
	}

	ports, advertised := matrixPorts(nodes, false)

	got := map[int]string{}
	for i, p := range ports {
		got[p.Port] = p.Name

		if i > 0 && ports[i-1].Port >= p.Port {
			t.Fatalf("ports are not sorted/deduped at %d: %+v", i, ports)
		}
	}
	for _, want := range []int{8091, 9100, 9999, 11207, 11210} {
		if _, ok := got[want]; !ok {
			t.Fatalf("expected port %d in matrix, got %+v", want, ports)
		}
	}
	if _, ok := got[0]; ok {
		t.Fatalf("zero port should not be probed: %+v", ports)
	}

	// Only the client-facing ports for this connection's scheme are advertised
	if !advertised[11210] {
		t.Fatalf("kv is a client-facing port, got %+v", advertised)
	}
	for _, unwanted := range []int{11207, 9100, 9999, 8091, 0} {
		if advertised[unwanted] {
			t.Fatalf("port %d should not be flagged for a plain connection, got %+v", unwanted, advertised)
		}
	}

	if _, advertised := matrixPorts(nodes, true); !advertised[11207] || advertised[11210] {
		t.Fatalf("a secured connection uses kvSSL and not kv, got %+v", advertised)
	}
}

func TestScanPortMatrixWarnsOnceForRefusedClientPorts(t *testing.T) {
	bindPort := func() (int, func()) {
		t.Helper()

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %s", err)
		}

		_, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := strconv.Atoi(portStr)

		return port, func() { ln.Close() }
	}

	openPort, closeOpen := bindPort()
	defer closeOpen()

	// Releasing the listener leaves a port that refuses rather than one that is filtered
	mgmtPort, closeMgmt := bindPort()
	closeMgmt()
	n1qlPort, closeN1ql := bindPort()
	closeN1ql()
	internalPort, closeInternal := bindPort()
	closeInternal()

	var out bytes.Buffer
	gLog = helpers.Logger{}
	gLog.SetOutput(&out)

	scanPortMatrix([]clusterNode{{
		Hostname: "127.0.0.1",
		Services: map[string]int{
			"kv": openPort, "mgmt": mgmtPort, "n1ql": n1qlPort, "indexAdmin": internalPort,
		},
	}}, false)

	// Two refused client ports on one host are one operator problem, so they warn once
	if warns := strings.Count(out.String(), "Cluster advertises"); warns != 1 {
		t.Fatalf("expected a single aggregated warning, got %d:\n%s", warns, out.String())
	}

	for _, want := range []string{
		strconv.Itoa(mgmtPort) + " (mgmt)",
		strconv.Itoa(n1qlPort) + " (n1ql)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("expected `%s` in the warning:\n%s", want, out.String())
		}
	}

	if strings.Contains(out.String(), "indexAdmin)") {
		t.Fatalf("internal services should not be warned about:\n%s", out.String())
	}
}

func TestProbePort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	if got := probePort("127.0.0.1", port, time.Second); got != "open" {
		t.Fatalf("listening port: expected open, got %s", got)
	}

	ln.Close()

	if got := probePort("127.0.0.1", port, time.Second); got != "refused" {
		t.Fatalf("closed port: expected refused, got %s", got)
	}
}

func TestTraceRequest(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, _ := http.NewRequest("GET", srv.URL, nil)
	req, phases := traceRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}
	resp.Body.Close()

	timing := phases()

	if timing.TCPStart.IsZero() || timing.TCP() <= 0 {
		t.Fatalf("tcp phase not recorded: %+v", timing)
	}
	if timing.TLSStart.IsZero() || timing.TLS() <= 0 {
		t.Fatalf("tls phase not recorded: %+v", timing)
	}

	if resp.TLS == nil {
		t.Fatal("expected TLS connection state on the response")
	}
}

func TestIsDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}
	closedAddr := ln.Addr().String()
	ln.Close()

	_, dialErr := net.Dial("tcp", closedAddr)
	if !isDialFailure(dialErr) {
		t.Fatalf("a refused dial is a dial failure, got %v", dialErr)
	}

	_, httpErr := http.Get("http://" + closedAddr)
	if !isDialFailure(httpErr) {
		t.Fatalf("a refused http dial is a dial failure, got %v", httpErr)
	}

	// An untrusted certificate must not be mistaken for an unreachable network
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	_, tlsErr := http.Get(srv.URL)
	if tlsErr == nil {
		t.Fatal("expected the default client to reject the test certificate")
	}
	if isDialFailure(tlsErr) {
		t.Fatalf("a TLS rejection is not a dial failure, got %v", tlsErr)
	}

	if isDialFailure(errors.New("invalid bucket name/password")) {
		t.Fatal("an auth rejection is not a dial failure")
	}
}

func TestHTTPProbeUnreachable(t *testing.T) {
	stalled := &url.Error{
		Op:  "Get",
		URL: "http://10.0.0.1:8091/",
		Err: context.DeadlineExceeded,
	}

	// A host dropping packets never completes the handshake, so the client timeout
	// fires with the TCP phase still open
	if !httpProbeUnreachable(stalled, memd.ConnectTiming{TCPStart: time.Now()}) {
		t.Fatal("a timeout before the handshake completed is unreachable")
	}

	// The same error from a service that accepted the connection and then stopped
	// answering is a stalled service, not an unroutable network
	connected := memd.ConnectTiming{TCPStart: time.Now(), TCPDone: time.Now()}
	if httpProbeUnreachable(stalled, connected) {
		t.Fatal("a timeout after the handshake completed is not unreachable")
	}

	// A refusal completes the TCP phase with an error, and stays a dial failure
	refused := &url.Error{
		Op:  "Get",
		URL: "http://127.0.0.1:1/",
		Err: &net.OpError{Op: "dial", Err: errors.New("connection refused")},
	}
	if !httpProbeUnreachable(refused, connected) {
		t.Fatal("a refused probe is unreachable")
	}
}

func TestTraceRequestPairsRacingConnects(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.invalid/", nil)
	req, phases := traceRequest(req)

	trace := httptrace.ContextClientTrace(req.Context())
	trace.ConnectStart("tcp", "[::1]:8091")
	time.Sleep(30 * time.Millisecond)
	trace.ConnectStart("tcp", "127.0.0.1:8091")
	trace.ConnectDone("tcp", "[::1]:8091", errors.New("no route to host"))
	trace.ConnectDone("tcp", "127.0.0.1:8091", nil)

	if got := phases().TCP(); got > 10*time.Millisecond {
		t.Fatalf("expected only the successful attempt to be timed, got %s", got)
	}
}

func TestTraceRequestLeavesFailedConnectUnstamped(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.invalid/", nil)
	req, phases := traceRequest(req)

	trace := httptrace.ContextClientTrace(req.Context())
	trace.ConnectStart("tcp", "127.0.0.1:8091")
	trace.ConnectDone("tcp", "127.0.0.1:8091", errors.New("connection refused"))

	timing := phases()
	if !timing.TCPDone.IsZero() {
		t.Fatalf("a failed connect must not stamp the phase, got %s", timing.TCPDone)
	}
	if !httpProbeUnreachable(errors.New("some wrapped error"), timing) {
		t.Fatal("expected an unfinished TCP phase to read as unreachable")
	}
}

func TestScanPortMatrixReportsBothRefusalDiagnoses(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	openPort, _ := strconv.Atoi(portStr)

	// The v6 loopback is a distinct address, so a v4-only listener is refused there
	if probePort("::1", openPort, time.Second) != "refused" {
		t.Skip("no usable IPv6 loopback to contrast against")
	}

	var out bytes.Buffer
	gLog = helpers.Logger{}
	gLog.SetOutput(&out)

	scanPortMatrix([]clusterNode{
		{Hostname: "127.0.0.1", Services: map[string]int{"mgmt": openPort}},
		{Hostname: "::1", Services: map[string]int{"mgmt": openPort}},
	}, false)

	for _, want := range []string{"Cluster advertises", "the service is down on those nodes"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("expected `%s` in the output:\n%s", want, out.String())
		}
	}
}
