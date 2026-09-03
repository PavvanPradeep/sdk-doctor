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

	if !httpProbeUnreachable(stalled, memd.ConnectTiming{TCPStart: time.Now()}) {
		t.Fatal("a timeout before the handshake completed is unreachable")
	}

	connected := memd.ConnectTiming{TCPStart: time.Now(), TCPDone: time.Now()}
	if httpProbeUnreachable(stalled, connected) {
		t.Fatal("a timeout after the handshake completed is not unreachable")
	}

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

func TestNetworkFromTerseBucketConfig(t *testing.T) {
	node := func(hostname string, alternate bool) bucketConfigNodeExt {
		ext := bucketConfigNodeExt{
			ThisNode: true,
			Hostname: hostname,
			Services: map[string]int{"kv": 11210, "mgmt": 8091},
		}

		if alternate {
			ext.AlternateNames = map[string]bucketConfigAlternateNames{
				"external": {Hostname: "node1.example.com", Ports: map[string]int{"kv": 32100}},
			}
		}

		return ext
	}

	tests := []struct {
		name   string
		config terseBucketConfig
		want   string
	}{
		{
			// The alternate addresses exist, but this client reached the node on its own network
			name: "bootstrapped on a default port",
			config: terseBucketConfig{
				SourceHost: "node1.internal", SourcePort: 11210,
				NodesExt: []bucketConfigNodeExt{node("node1.internal", true)},
			},
			want: "default",
		},
		{
			name: "bootstrapped on an alternate port",
			config: terseBucketConfig{
				SourceHost: "node1.example.com", SourcePort: 32100,
				NodesExt: []bucketConfigNodeExt{node("node1.internal", true)},
			},
			want: "external",
		},
		{
			// Couchbase omits the hostname of the node answering the request
			name: "node advertises no hostname",
			config: terseBucketConfig{
				SourceHost: "node1.internal", SourcePort: 8091,
				NodesExt: []bucketConfigNodeExt{node("", true)},
			},
			want: "default",
		},
		{
			name: "no alternate addresses configured",
			config: terseBucketConfig{
				SourceHost: "node1.internal", SourcePort: 11210,
				NodesExt: []bucketConfigNodeExt{node("node1.internal", false)},
			},
			want: "default",
		},
		{
			// An alternate network can remap only the port, advertising no hostname of its own
			name: "bootstrapped on an alternate port with no alternate hostname",
			config: terseBucketConfig{
				SourceHost: "node1.internal", SourcePort: 32100,
				NodesExt: []bucketConfigNodeExt{{
					ThisNode: true,
					Hostname: "node1.internal",
					Services: map[string]int{"kv": 11210, "mgmt": 8091},
					AlternateNames: map[string]bucketConfigAlternateNames{
						"external": {Ports: map[string]int{"kv": 32100}},
					},
				}},
			},
			want: "external",
		},
	}

	for _, test := range tests {
		if got := networkFromTerseBucketConfig(test.config); got != test.want {
			t.Errorf("%s: expected `%s`, got `%s`", test.name, test.want, got)
		}
	}
}

func TestNetworkFromTerseBucketConfigIsDeterministic(t *testing.T) {
	config := terseBucketConfig{
		SourceHost: "node1.example.com", SourcePort: 32100,
		NodesExt: []bucketConfigNodeExt{{
			ThisNode: true,
			Hostname: "node1.internal",
			Services: map[string]int{"kv": 11210},
			AlternateNames: map[string]bucketConfigAlternateNames{
				"external":  {Hostname: "node1.example.com", Ports: map[string]int{"kv": 32100}},
				"external2": {Hostname: "node1.example.com", Ports: map[string]int{"kv": 32100}},
			},
		}},
	}

	// Map iteration order is randomized per range, so a run without sorted keys would be
	// unlikely to return the same network every time across enough repetitions
	for i := 0; i < 20; i++ {
		if got := networkFromTerseBucketConfig(config); got != "external" {
			t.Fatalf("run %d: expected the alphabetically-first match `external`, got `%s`", i, got)
		}
	}
}

func TestIsConnRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}

	addr := ln.Addr().String()
	ln.Close()

	_, refusedErr := net.DialTimeout("tcp", addr, time.Second)
	if refusedErr == nil {
		t.Skip("the released port was taken by another listener")
	}

	if !isConnRefused(refusedErr) {
		t.Fatalf("expected a refusal for %s, got %v", addr, refusedErr)
	}

	_, dnsErr := net.DialTimeout("tcp", "no-such-host.invalid:80", time.Second)
	if dnsErr == nil || isConnRefused(dnsErr) {
		t.Fatalf("expected a lookup failure to not be a refusal, got %v", dnsErr)
	}
}

// A refused TCP connection must be reported at the TCP phase, not the DNS phase: the
// httptrace hook that would otherwise prove a successful connect never fires on a
// refusal, so the phase has to be inferred from the error itself, not from timing alone.
func TestFetchHTTPTerseBucketConfigReportsARefusedPortAsTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close()

	_, refusedErr := net.DialTimeout("tcp", addr.String(), time.Second)
	if refusedErr == nil {
		t.Skip("the released port was taken by another listener")
	}

	_, gotAttempt, err := fetchHTTPTerseBucketConfig("127.0.0.1", addr.Port, "default", "u", "p", nil)
	if err == nil {
		t.Fatal("expected a connection-refused error, got nil")
	}

	if gotAttempt.Phase != string(helpers.PhaseTCP) {
		t.Errorf("phase = %q, want %q (err was: %v)", gotAttempt.Phase, helpers.PhaseTCP, err)
	}
	if gotAttempt.Category != string(helpers.CategoryTCPRefused) {
		t.Errorf("category = %q, want %q", gotAttempt.Category, helpers.CategoryTCPRefused)
	}
}

// A rejected server certificate must be reported at the TLS phase, not the TCP phase:
// httptrace stamps TLSHandshakeDone even when the handshake fails, so a naive "TLS
// finished cleanly" check can't tell a completed handshake from a rejected one.
func TestFetchHTTPTerseBucketConfigReportsARejectedCertAsTLS(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	// A non-nil but otherwise default config: default certificate verification applies,
	// and the server's self-signed cert is not in any trust store this test controls.
	tlsConfig := &tls.Config{}

	_, gotAttempt, err := fetchHTTPTerseBucketConfig(host, port, "default", "u", "p", tlsConfig)
	if err == nil {
		t.Fatal("expected a certificate verification error, got nil")
	}

	if gotAttempt.Phase != string(helpers.PhaseTLS) {
		t.Errorf("phase = %q, want %q (err was: %v)", gotAttempt.Phase, helpers.PhaseTLS, err)
	}
	if gotAttempt.Category != string(helpers.CategoryTLSVerify) {
		t.Errorf("category = %q, want %q", gotAttempt.Category, helpers.CategoryTLSVerify)
	}
}

// A server that completes the TCP handshake and then never answers (a hung mgmt port, a
// stalling proxy, an overloaded node) must be reported at the response phase, not the TCP
// phase: timing.TCPDone is stamped only when a connect succeeds, so it is the "we reached
// the server" signal even though the request itself never got an answer. Misclassifying
// this at PhaseTCP would make reachedPastTCP false and emit the legacy "unreachable"
// sentence for an endpoint that was demonstrably reached.
func TestFetchHTTPTerseBucketConfigReportsAHungServerAsResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}
	defer ln.Close()

	// Accept every connection and never write a response. The goroutine exits on its own
	// once the client (after its own timeout) drops the connection.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)

	_, gotAttempt, err := fetchHTTPTerseBucketConfig("127.0.0.1", addr.Port, "default", "u", "p", nil)
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}

	if gotAttempt.Phase != string(helpers.PhaseResponse) {
		t.Errorf("phase = %q, want %q (err was: %v)", gotAttempt.Phase, helpers.PhaseResponse, err)
	}

	summary := bootstrapSummary([]helpers.Attempt{gotAttempt}, "default")
	if strings.Contains(summary, "unreachable") {
		t.Errorf("a hung server that completed the TCP handshake must not be reported as"+
			" unreachable, got: %s", summary)
	}
}
