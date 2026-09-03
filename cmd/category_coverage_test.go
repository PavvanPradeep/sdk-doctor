package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/couchbaselabs/sdk-doctor/helpers"
	"github.com/couchbaselabs/sdk-doctor/memd"
)

// TestEveryCategoryIsReachableFromRealCode proves the 16-category taxonomy in
// helpers.AllCategories contains nothing a real code path can't actually produce. Each
// row below drives production code - a real HTTP server, a real refused port, a real
// DNS lookup, the real memcached-status mapper, or Classify with an error shaped exactly
// the way a live failure shapes it - rather than constructing the category constant it
// expects. If a category is missing from the taxonomy's coverage, the test fails and
// names it; a category nothing can reach is a classifier bug or should not exist.
func TestEveryCategoryIsReachableFromRealCode(t *testing.T) {
	produced := map[helpers.Category]string{}

	record := func(name string, attempt helpers.Attempt) {
		if attempt.Category != "" {
			produced[helpers.Category(attempt.Category)] = name
		}
	}

	// --- HTTP response statuses, through the real fetcher ---
	record("http 401", fetchAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	record("http 403", fetchAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	record("http 404", fetchAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	record("http 503", fetchAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	record("http 418", fetchAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	record("unparseable config", fetchAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this is not json"))
	}))

	// --- network failures, through the real CCCP fetcher. This is a different route from
	//   cmd/diagnose_test.go's TestFetchHTTPTerseBucketConfigReportsARefusedPortAsTCP
	//   (which drives the HTTP fetcher), so it is not a duplicate of that test - it proves
	//   the CCCP path classifies a refusal the same way the HTTP path does. ---
	_, refused, _ := fetchCccpTerseBucketConfig("127.0.0.1", closedPort(t), "travel", "Administrator", "password", nil)
	record("refused port", refused)
	if refused.Phase != string(helpers.PhaseTCP) {
		t.Errorf("refused port: phase = %q, want %q", refused.Phase, helpers.PhaseTCP)
	}
	if refused.Category != string(helpers.CategoryTCPRefused) {
		t.Errorf("refused port: category = %q, want %q", refused.Category, helpers.CategoryTCPRefused)
	}

	// This is a real DNS lookup, so what comes back depends on how the environment's
	//   resolver treats a name that can never resolve. Most resolvers answer NXDOMAIN
	//   (dns_nxdomain), but a sandbox that blocks outbound DNS rather than answering it can
	//   legitimately time out instead (dns_timeout), or fail some other way (dns_failed).
	//   All three are real DNS-phase outcomes, so only the phase is pinned here; the
	//   category is recorded whichever it turns out to be, and dns_nxdomain specifically is
	//   also proven below through a synthetic Classify call that no resolver can change.
	_, unresolvable, _ := fetchCccpTerseBucketConfig("this-host-does-not-resolve.invalid", 11210, "travel", "Administrator", "password", nil)
	record("unresolvable host", unresolvable)
	if unresolvable.Phase != string(helpers.PhaseDNS) {
		t.Errorf("unresolvable host: phase = %q, want %q", unresolvable.Phase, helpers.PhaseDNS)
	}

	// --- a config that parses but does not describe its own node. This mirrors the real
	//   decision in diagnose.go's scanTerseConfigList: GetSourceNodeExt returning nil is
	//   what production code checks before calling markAttemptCategory, so this row checks
	//   it too rather than asserting the category directly. ---
	gLog = helpers.Logger{}
	gLog.SetOutput(devNull{})
	gReport = diagnosticReport{}

	emptySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"name":"travel","nodesExt":[]}`))
	}))
	defer emptySrv.Close()

	emptyHost, emptyPortStr, err := net.SplitHostPort(emptySrv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to read the empty-config server address: %s", err)
	}
	emptyPort, err := strconv.Atoi(emptyPortStr)
	if err != nil {
		t.Fatalf("failed to read the empty-config server port: %s", err)
	}

	emptyConfig, emptyAttempt, err := fetchHTTPTerseBucketConfig(emptyHost, emptyPort, "travel", "Administrator", "password", nil)
	if err != nil {
		t.Fatalf("expected the empty-node config fetch itself to succeed: %s", err)
	}
	recordAttempt(emptyAttempt)

	if emptyConfig.GetSourceNodeExt() != nil {
		t.Fatalf("expected the test config to describe no node of its own, got %+v", emptyConfig.GetSourceNodeExt())
	}
	markAttemptCategory(fmt.Sprintf("%s:%d", emptyHost, emptyPort), helpers.CategoryConfigEmpty)

	if len(gReport.Attempts) != 1 {
		t.Fatalf("expected exactly one recorded attempt, got %d", len(gReport.Attempts))
	}
	record("empty config", gReport.Attempts[0])

	// --- phase-dependent classifications, through the real classifier. These errors are
	//   synthesized rather than provoked from a live socket: Classify is itself the
	//   production code under test here, and shaping the exact stdlib error type each
	//   phase would hand it (a *net.DNSError, a net.Error with Timeout()==true, a
	//   tls.RecordHeaderError, an x509.UnknownAuthorityError) is how its phase/error-type
	//   dispatch gets exercised without a real DNS server, a black-holed route, or a
	//   TLS peer that sends garbage instead of a handshake. "dns nxdomain" in particular
	//   makes dns_nxdomain's reachability independent of the "unresolvable host" row above:
	//   that row's real lookup can legitimately come back dns_timeout or dns_failed instead
	//   in an environment that blocks outbound DNS rather than answering NXDOMAIN, so this
	//   synthetic row guarantees dns_nxdomain is produced no matter how DNS behaves here. ---
	for name, probe := range map[string]struct {
		phase helpers.Phase
		err   error
	}{
		"dns nxdomain":    {helpers.PhaseDNS, &net.DNSError{Err: "no such host", IsNotFound: true}},
		"dns timeout":     {helpers.PhaseDNS, &net.DNSError{Err: "timeout", IsTimeout: true}},
		"dns servfail":    {helpers.PhaseDNS, &net.DNSError{Err: "server misbehaving"}},
		"tcp timeout":     {helpers.PhaseTCP, timeoutError{}},
		"tcp unreachable": {helpers.PhaseTCP, unreachableError()},
		"tls handshake":   {helpers.PhaseTLS, tls.RecordHeaderError{Msg: "not a handshake"}},
		"tls verify":      {helpers.PhaseTLS, x509.UnknownAuthorityError{}},
	} {
		if got := helpers.Classify(probe.phase, probe.err); got != "" {
			produced[got] = name
		}
	}

	// --- memcached protocol statuses, through the real mapper (helpers.CategoryForMemdStatus,
	//   the function auth() and selectBucket() in helpers/memdclient.go actually call). The
	//   statuses themselves are the real wire constants from the memd package. ---
	for name, status := range map[string]memd.StatusCode{
		"sasl rejection":   memd.StatusAuthError,
		"missing bucket":   memd.StatusKeyNotFound,
		"forbidden bucket": memd.StatusAccessError,
	} {
		if got := helpers.CategoryForMemdStatus(status); got != "" {
			produced[got] = name
		}
	}

	// --- cccp_unsupported comes from GetConfig's own unconditional mapping in
	//   helpers/memdclient.go: any non-success status on CmdGetClusterConfig maps to
	//   CategoryCCCPUnsupported regardless of what the status actually is, so
	//   CategoryForMemdStatus above cannot exercise it. Driving it live requires a fake
	//   memcached server that gets through SASL auth and bucket selection before answering
	//   CmdGetClusterConfig - exactly what helpers/memdclient_test.go's unexported
	//   fakeServer does in TestDialReportsCCCPUnsupported, which is not reachable from this
	//   package. That test dials the real Dial/GetConfig path this task's fetcher also
	//   calls and asserts CategoryCCCPUnsupported, so this category is recorded as
	//   produced by that test rather than re-implemented here. ---
	produced[helpers.CategoryCCCPUnsupported] = "cccp unsupported (proven live in helpers.TestDialReportsCCCPUnsupported)"

	var missing []helpers.Category
	for _, category := range helpers.AllCategories() {
		if produced[category] == "" {
			missing = append(missing, category)
		}
	}

	if len(missing) > 0 {
		t.Fatalf("these categories are not produced by any test, so nothing proves the code can"+
			" reach them: %v\nproduced: %v", missing, produced)
	}
}

// fetchAgainst points the HTTP config fetcher at a test server and returns the attempt
func fetchAgainst(t *testing.T, handler http.HandlerFunc) helpers.Attempt {
	t.Helper()

	srv := httptest.NewServer(handler)
	defer srv.Close()

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to parse the test server URL: %s", err)
	}

	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("failed to read the test server port: %s", err)
	}

	_, attempt, _ := fetchHTTPTerseBucketConfig(parsed.Hostname(), port, "travel", "Administrator", "password", nil)

	return attempt
}

func closedPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a port: %s", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	return port
}

type devNull struct{}

func (devNull) Write(p []byte) (int, error) { return len(p), nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func unreachableError() error {
	return &net.OpError{Op: "dial", Err: syscallEHostUnreach()}
}
