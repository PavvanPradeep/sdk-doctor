package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/couchbaselabs/sdk-doctor/helpers"
	"github.com/couchbaselabs/sdk-doctor/memd"
)

// Every row drives production code, so a category nothing can reach fails the test by name
func TestEveryCategoryIsReachableFromRealCode(t *testing.T) {
	produced := map[helpers.Category]string{}

	record := func(name string, attempt helpers.Attempt) {
		if attempt.Category != "" {
			produced[helpers.Category(attempt.Category)] = name
		}
	}

	// HTTP response statuses, through the real fetcher
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
	produced[helpers.CategoryForServiceHTTPStatus(http.StatusForbidden)] = "service http 403"
	record("unparseable config", fetchAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this is not json"))
	}))

	// Network failures through the CCCP fetcher, proving it classifies a refusal as HTTP does
	_, refused, _ := fetchCccpTerseBucketConfig("127.0.0.1", closedPort(t), "travel", "Administrator", "password", nil)
	record("refused port", refused)
	if refused.Phase != string(helpers.PhaseTCP) {
		t.Errorf("refused port: phase = %q, want %q", refused.Phase, helpers.PhaseTCP)
	}
	if refused.Category != string(helpers.CategoryTCPRefused) {
		t.Errorf("refused port: category = %q, want %q", refused.Category, helpers.CategoryTCPRefused)
	}

	// A real lookup, so only the phase is pinned, and only when the name actually fails to resolve
	const unresolvableHost = "this-host-does-not-resolve.invalid"

	_, unresolvable, _ := fetchCccpTerseBucketConfig(unresolvableHost, 11210, "travel", "Administrator", "password", nil)
	record("unresolvable host", unresolvable)
	if _, lookupErr := net.LookupHost(unresolvableHost); lookupErr != nil {
		if unresolvable.Phase != string(helpers.PhaseDNS) {
			t.Errorf("unresolvable host: phase = %q, want %q", unresolvable.Phase, helpers.PhaseDNS)
		}
	} else {
		t.Logf("skipping the DNS-phase assertion: this resolver answers for %q", unresolvableHost)
	}

	// A config that parses but describes no node of its own, checked as scanTerseConfigList does
	defer saveGlobals()()

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

	// Driven through real code, so an unreachable category cannot be faked by the test itself
	if nodes := nodesFromMasterConfig(emptyConfig, "default"); nodes != nil {
		t.Fatalf("expected no node list from an empty config, got %+v", nodes)
	}

	if len(gReport.Attempts) != 1 {
		t.Fatalf("expected exactly one recorded attempt, got %d", len(gReport.Attempts))
	}
	record("empty config", gReport.Attempts[0])

	// Phase-dependent classifications, with errors shaped the way the stdlib shapes them
	for name, probe := range map[string]struct {
		phase helpers.Phase
		err   error
	}{
		"dns nxdomain":     {helpers.PhaseDNS, &net.DNSError{Err: "no such host", IsNotFound: true}},
		"dns timeout":      {helpers.PhaseDNS, &net.DNSError{Err: "timeout", IsTimeout: true}},
		"dns servfail":     {helpers.PhaseDNS, &net.DNSError{Err: "server misbehaving"}},
		"tcp timeout":      {helpers.PhaseTCP, timeoutError{}},
		"tcp unreachable":  {helpers.PhaseTCP, unreachableError()},
		"tls handshake":    {helpers.PhaseTLS, tls.RecordHeaderError{Msg: "not a handshake"}},
		"tls verify":       {helpers.PhaseTLS, x509.UnknownAuthorityError{}},
		"response timeout": {helpers.PhaseResponse, timeoutError{}},
	} {
		if got := helpers.Classify(probe.phase, probe.err); got != "" {
			produced[got] = name
		}
	}

	// Memcached statuses, through the real mapper auth() and selectBucket() call
	for name, status := range map[string]memd.StatusCode{
		"sasl rejection":   memd.StatusAuthError,
		"missing bucket":   memd.StatusKeyNotFound,
		"forbidden bucket": memd.StatusAccessError,
	} {
		if got := helpers.CategoryForMemdStatus(status); got != "" {
			produced[got] = name
		}
	}

	// cccp_unsupported through the mapper GetConfig calls, so no category is asserted by fiat
	for name, status := range map[string]memd.StatusCode{
		"cccp unsupported": memd.StatusUnknownCommand,
		"no configuration": memd.StatusKeyNotFound,
	} {
		if got := helpers.CategoryForConfigStatus(status); got != "" {
			produced[got] = name
		}
	}

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
