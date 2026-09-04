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

	"github.com/couchbaselabs/gocbconnstr"
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
		{Hostname: "a", Services: map[string]int{
			"indexAdmin": 9100, "kv": 11210, "kvSSL": 11207, "mgmt": 8091, "n1ql": 8093,
		}},
		{Hostname: "b", Services: map[string]int{
			"projector": 9999, "capi": 0, "kv": 11210, "mgmt": 8091,
		}},
	}

	ports := matrixPorts(nodes, false)

	got := map[int]string{}
	for i, p := range ports {
		got[p.Port] = p.Name

		if i > 0 && ports[i-1].Port >= p.Port {
			t.Fatalf("ports are not sorted/deduped at %d: %+v", i, ports)
		}
	}
	for _, want := range []int{8091, 8093, 9100, 9999, 11207, 11210} {
		if _, ok := got[want]; !ok {
			t.Fatalf("expected port %d in matrix, got %+v", want, ports)
		}
	}
	if _, ok := got[0]; ok {
		t.Fatalf("zero port should not be probed: %+v", ports)
	}

	if !nodeAdvertisesPort(nodes[0], 8093, false) {
		t.Fatal("node a runs n1ql, so it should advertise 8093")
	}
	if nodeAdvertisesPort(nodes[1], 8093, false) {
		t.Fatal("node b does not run n1ql, so it must not advertise 8093")
	}

	for _, unwanted := range []int{0, 9100, 9999, 11207} {
		if nodeAdvertisesPort(nodes[0], unwanted, false) {
			t.Fatalf("port %d should not be advertised for a plain connection", unwanted)
		}
	}

	if !nodeAdvertisesPort(nodes[0], 11207, true) || nodeAdvertisesPort(nodes[0], 11210, true) {
		t.Fatal("a secured connection should use kvSSL and not kv")
	}

	unresolved := []clusterNode{
		{Hostname: "reachable", Services: map[string]int{"n1ql": 8093}},
		{Hostname: "does-not-resolve.invalid", Services: map[string]int{"n1ql": 8093}},
	}
	if got := countAdvertisingNodes(unresolved, 8093, false); got != 2 {
		t.Fatalf("DNS must not shrink the advertising-node denominator: got %d, want 2", got)
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

	defer saveGlobals()()

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

func TestScanPortMatrixSkipsNodesNotAdvertisingAPort(t *testing.T) {
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

	kvPort, closeKv := bindPort()
	defer closeKv()

	n1qlPort, closeN1ql := bindPort()
	closeN1ql()

	defer saveGlobals()()

	var out bytes.Buffer
	gLog = helpers.Logger{}
	gLog.SetOutput(&out)

	scanPortMatrix([]clusterNode{
		{Hostname: "127.0.0.1", Services: map[string]int{"kv": kvPort, "n1ql": n1qlPort}},
		{Hostname: "127.0.0.1", Services: map[string]int{"kv": kvPort}},
	}, false)

	if warns := strings.Count(out.String(), "Cluster advertises"); warns != 1 {
		t.Fatalf("expected a single warning for the one node advertising n1ql, got %d:\n%s", warns, out.String())
	}

	if !strings.Contains(out.String(), "on `127.0.0.1` which refuse connections") {
		t.Fatalf("the node that does not advertise n1ql must not be named:\n%s", out.String())
	}

	if strings.Contains(out.String(), "but open on") {
		t.Fatalf("a port only one node advertises cannot be open elsewhere:\n%s", out.String())
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
	req, phases, _ := traceRequest(req)

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
	req, phases, _ := traceRequest(req)

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
	req, phases, _ := traceRequest(req)

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

	defer saveGlobals()()

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

	// Map order is randomized per range, so unsorted keys would not survive this many runs
	for i := 0; i < 20; i++ {
		if got := networkFromTerseBucketConfig(config); got != "external" {
			t.Fatalf("run %d: expected the alphabetically-first match `external`, got `%s`", i, got)
		}
	}
}

// A refusal never fires the connect hook, so the phase comes from the error, not the timing
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

// TLSHandshakeDone is stamped even on failure, so "TLS finished" cannot mean "TLS succeeded"
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

	// A default config verifies certificates, and this server's is in no trust store
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

// TCPDone is stamped only on a successful connect, so a hung server was still reached
func TestFetchHTTPTerseBucketConfigReportsAHungServerAsResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}
	defer ln.Close()

	// Accept and never answer; the goroutine exits when the client drops the connection
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

// Both HTTP paths decide here, so every branch is pinned rather than only the ones a caller hits
func TestHTTPFailurePhase(t *testing.T) {
	now := time.Now()

	connected := memd.ConnectTiming{TCPStart: now, TCPDone: now}
	handshaking := memd.ConnectTiming{TCPStart: now, TCPDone: now, TLSStart: now}

	tests := []struct {
		name             string
		timing           memd.ConnectTiming
		tlsHandshakeDone bool
		err              error
		want             helpers.Phase
	}{
		{"lookup failed", memd.ConnectTiming{}, false, &net.DNSError{Err: "no such host"}, helpers.PhaseDNS},
		{"never connected", memd.ConnectTiming{TCPStart: now}, false, context.DeadlineExceeded, helpers.PhaseTCP},
		{"handshake failed", handshaking, false, errors.New("bad certificate"), helpers.PhaseTLS},
		{"handshake done, no answer", handshaking, true, context.DeadlineExceeded, helpers.PhaseResponse},
		{"connected, no answer", connected, false, context.DeadlineExceeded, helpers.PhaseResponse},
	}

	for _, test := range tests {
		got := httpFailurePhase(test.timing, test.tlsHandshakeDone, test.err)
		if got != test.want {
			t.Errorf("%s: phase = %q, want %q", test.name, got, test.want)
		}
	}
}

// Inferring from TLSStart alone blamed trust configuration for a cert the client had accepted
func TestFetchHTTPTerseBucketConfigReportsAHungTLSServerAsResponse(t *testing.T) {
	release := make(chan struct{})

	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		// Outlive the fetcher's budget, so it times out with the handshake already behind it
		<-release
	}))
	defer srv.Close()
	defer close(release)

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to parse the test server URL: %s", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("failed to read the test server port: %s", err)
	}

	// The handshake must succeed here, so the server's certificate is accepted, not verified
	_, gotAttempt, err := fetchHTTPTerseBucketConfig(parsed.Hostname(), port, "default", "u", "p",
		&tls.Config{InsecureSkipVerify: true})
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}

	if gotAttempt.Phase != string(helpers.PhaseResponse) {
		t.Errorf("phase = %q, want %q (err was: %v)", gotAttempt.Phase, helpers.PhaseResponse, err)
	}
	if gotAttempt.Category != string(helpers.CategoryResponseTimeout) {
		t.Errorf("category = %q, want %q", gotAttempt.Category, helpers.CategoryResponseTimeout)
	}

	summary := bootstrapSummary([]helpers.Attempt{gotAttempt}, "default")
	for _, wrong := range []string{"unreachable", "TLS handshake failed"} {
		if strings.Contains(summary, wrong) {
			t.Errorf("a server that completed its handshake and then stalled must not be"+
				" reported with %q, got: %s", wrong, summary)
		}
	}

	// An unranked category falls back to a generic line that would pass the checks above
	if !strings.Contains(summary, "stopped responding") {
		t.Errorf("expected the summary to name the stall, got: %s", summary)
	}
}

// Selecting the config and only then rejecting it printed "cannot be used" and used it anyway
func TestScanTerseConfigListRejectsAConfigThatDescribesNoNodeOfItsOwn(t *testing.T) {
	defer saveGlobals()()

	var out bytes.Buffer
	gLog = helpers.Logger{}
	gLog.SetOutput(&out)
	gReport = diagnosticReport{}
	gReport.Attempts = []helpers.Attempt{
		attempt("bootstrap-http-terse", "hostA:8091", helpers.PhaseConfig, ""),
	}

	hosts := []gocbconnstr.Address{{Host: "hostA", Port: 8091}}
	configs := []*terseBucketConfig{{
		UUID:     "abc",
		NodesExt: []bucketConfigNodeExt{{Hostname: "hostB", Services: map[string]int{"kv": 11210}}},
	}}

	if got := scanTerseConfigList(hosts, configs); got != nil {
		t.Errorf("expected no usable master config, got %+v", got)
	}

	if !strings.Contains(out.String(), "does not describe the node") {
		t.Errorf("expected the rejection to be reported, got:\n%s", out.String())
	}

	if got := gReport.Attempts[0].Category; got != string(helpers.CategoryConfigEmpty) {
		t.Errorf("attempt category = %q, want %q", got, helpers.CategoryConfigEmpty)
	}
}

// A later host's good configuration must still be usable after an earlier one was rejected
func TestScanTerseConfigListFallsThroughToTheNextUsableConfig(t *testing.T) {
	defer saveGlobals()()

	gLog = helpers.Logger{}
	gLog.SetOutput(devNull{})
	gReport = diagnosticReport{}

	hosts := []gocbconnstr.Address{{Host: "hostA", Port: 8091}, {Host: "hostB", Port: 8091}}
	configs := []*terseBucketConfig{
		{UUID: "abc", NodesExt: []bucketConfigNodeExt{{Hostname: "hostZ"}}},
		{UUID: "def", NodesExt: []bucketConfigNodeExt{{ThisNode: true, Hostname: "hostB"}}},
	}

	got := scanTerseConfigList(hosts, configs)
	if got == nil {
		t.Fatal("expected the second host's config to be selected")
	}
	if got.UUID != "def" {
		t.Errorf("selected config UUID = %q, want the second host's %q", got.UUID, "def")
	}
}

// Every attempt succeeds in this case, so without a report the run names no cause at all
func TestNodesFromMasterConfigReportsAMissingAlternateNetwork(t *testing.T) {
	defer saveGlobals()()

	var out bytes.Buffer
	gLog = helpers.Logger{}
	gLog.SetOutput(&out)
	gReport = diagnosticReport{}
	gReport.Attempts = []helpers.Attempt{
		attempt("bootstrap-http-terse", "hostA:8091", helpers.PhaseConfig, ""),
	}

	config := terseBucketConfig{
		SourceHost: "hostA",
		SourcePort: 8091,
		NodesExt: []bucketConfigNodeExt{
			{ThisNode: true, Hostname: "hostA", Services: map[string]int{"kv": 11210},
				AlternateNames: map[string]bucketConfigAlternateNames{
					"external": {Hostname: "ext-a"},
				}},
			// This node advertises no external address, so the list cannot be completed
			{Hostname: "hostB", Services: map[string]int{"kv": 11210}},
		},
	}

	if got := nodesFromMasterConfig(config, "external"); got != nil {
		t.Errorf("expected no node list, got %+v", got)
	}

	if !strings.Contains(out.String(), "does not describe the `external` network") {
		t.Errorf("expected the missing network to be reported, got:\n%s", out.String())
	}

	if got := gReport.Attempts[0].Category; got != string(helpers.CategoryConfigInvalid) {
		t.Errorf("attempt category = %q, want %q", got, helpers.CategoryConfigInvalid)
	}

	summary := bootstrapSummary(gReport.Attempts, "travel")
	if !strings.Contains(summary, "could not use") {
		t.Errorf("expected the summary to name the unusable configuration, got: %s", summary)
	}
}

// The default network needs no alternate entry, so the same config yields every node
func TestNodesFromMasterConfigKeepsTheDefaultNetwork(t *testing.T) {
	defer saveGlobals()()

	gLog = helpers.Logger{}
	gLog.SetOutput(devNull{})
	gReport = diagnosticReport{}

	config := terseBucketConfig{
		SourceHost: "hostA",
		NodesExt: []bucketConfigNodeExt{
			{ThisNode: true, Hostname: "hostA"},
			{Hostname: "hostB"},
		},
	}

	if got := nodesFromMasterConfig(config, "default"); len(got) != 2 {
		t.Errorf("expected both nodes, got %+v", got)
	}
}
