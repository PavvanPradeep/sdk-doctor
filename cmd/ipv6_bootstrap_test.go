package cmd

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/couchbaselabs/sdk-doctor/helpers"
	"github.com/couchbaselabs/sdk-doctor/memd"
)

func TestFetchTerseConfigReachesABracketedIPv6Endpoint(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host: %s", err)
	}

	srv := &httptest.Server{
		Listener: ln,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"uuid":"abc","nodesExt":[{"hostname":"$HOST","services":{"kv":11210}}]}`)
		})},
	}
	srv.Start()
	defer srv.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	config, attempt, err := fetchHTTPTerseBucketConfig("[::1]", port, "travel", "Administrator", "password", nil)
	if err != nil {
		t.Fatalf("bracketed IPv6 host failed to bootstrap: %s", err)
	}

	if attempt.Endpoint != helpers.HostPort("::1", port) {
		t.Errorf("endpoint = %q, want %q", attempt.Endpoint, helpers.HostPort("::1", port))
	}

	if _, _, err := net.SplitHostPort(attempt.Endpoint); err != nil {
		t.Errorf("endpoint %q cannot be read back: %s", attempt.Endpoint, err)
	}

	if config.UUID != "abc" {
		t.Errorf("config was not parsed: uuid = %q", config.UUID)
	}
}

func TestFetchTerseConfigReportsAnUnusableAddressInsteadOfPanicking(t *testing.T) {
	for _, host := range []string{"bad host", "host\x7f", "ho%st"} {
		_, attempt, err := fetchHTTPTerseBucketConfig(host, 8091, "travel", "Administrator", "password", nil)
		if err == nil {
			t.Errorf("host %q: expected an error, got none", host)
			continue
		}

		if attempt.Error == "" {
			t.Errorf("host %q: the attempt recorded no error", host)
		}
	}
}

func TestFetchTerseConfigDoesNotFollowARedirectWithCredentials(t *testing.T) {
	var sawAuth string

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, `{"uuid":"leaked"}`)
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/sso", http.StatusFound)
	}))
	defer origin.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	if err != nil {
		t.Fatalf("failed to split the test server address: %s", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to read the test server port: %s", err)
	}

	_, attempt, err := fetchHTTPTerseBucketConfig(host, port, "travel", "Administrator", "SUPERSECRET", nil)
	if err == nil {
		t.Error("the redirect was followed and treated as a successful bootstrap")
	}

	if sawAuth != "" {
		t.Errorf("the redirect target received the credentials: %q", sawAuth)
	}

	if attempt.Phase != string(helpers.PhaseResponse) {
		t.Errorf("phase = %q, want %q: the redirect is the server's own answer",
			attempt.Phase, helpers.PhaseResponse)
	}
}

func TestOnlyTheManagementProbeSendsCredentials(t *testing.T) {
	for _, svc := range []string{"mgmt", "capi", "n1ql", "fts", "cbas"} {
		want := svc == "mgmt"
		if got := probeNeedsCredentials(svc); got != want {
			t.Errorf("probeNeedsCredentials(%q) = %t, want %t", svc, got, want)
		}
	}
}

func TestTraceAccessorsReturnCopies(t *testing.T) {
	trace := &httpTrace{starts: map[string]time.Time{}}
	trace.resolved = []string{"10.0.0.1"}
	trace.addresses = []memd.AddressResult{{Address: "10.0.0.1:8091"}}

	resolved := trace.Resolved()
	addresses := trace.Addresses()

	trace.lock.Lock()
	trace.resolved[0] = "MUTATED"
	trace.addresses[0].Local = "MUTATED"
	trace.lock.Unlock()

	if resolved[0] != "10.0.0.1" {
		t.Errorf("Resolved() aliased the live slice: %q", resolved[0])
	}

	if addresses[0].Local != "" {
		t.Errorf("Addresses() aliased the live slice: %q", addresses[0].Local)
	}
}

func TestFetchTerseConfigEscapesABucketNameWithAPercent(t *testing.T) {
	const bucket = "my%bucket"

	var gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte(`{"uuid":"percent-ok","nodesExt":[]}`))
	}))
	defer srv.Close()

	host, port := splitTestServer(t, srv)

	config, attempt, err := fetchHTTPTerseBucketConfig(host, port, bucket,
		"Administrator", "password", nil)
	if err != nil {
		t.Fatalf("fetching a config for bucket %q failed: %s (category %q)",
			bucket, err, attempt.Category)
	}

	if want := "/pools/default/b/" + bucket; gotPath != want {
		t.Errorf("the server saw path %q, want %q", gotPath, want)
	}

	if config.UUID != "percent-ok" {
		t.Errorf("config was not parsed: uuid = %q", config.UUID)
	}
}

func TestFetchTerseConfigReachesAZonedIPv6Endpoint(t *testing.T) {
	host, zone := linkLocalAddress(t)

	ln, err := net.Listen("tcp6", helpers.HostPort(host+"%"+zone, 0))
	if err != nil {
		t.Skipf("cannot listen on link-local %s%%%s: %s", host, zone, err)
	}

	srv := &httptest.Server{
		Listener: ln,
		Config: &http.Server{Handler: http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"uuid":"zoned-ok","nodesExt":[{"hostname":"$HOST",` +
					`"services":{"kv":11210,"mgmt":8091}}]}`))
			})},
	}
	srv.Start()
	defer srv.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	spelling := host + "%" + zone

	config, attempt, err := fetchHTTPTerseBucketConfig(spelling, port, "travel",
		"Administrator", "password", nil)
	if err != nil {
		t.Fatalf("fetching a config from %q failed: %s (phase %q, category %q)",
			helpers.HostPort(spelling, port), err, attempt.Phase, attempt.Category)
	}

	if config.UUID != "zoned-ok" {
		t.Errorf("config from %q was not parsed: uuid = %q", spelling, config.UUID)
	}
}

func linkLocalAddress(t *testing.T) (string, string) {
	t.Helper()

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %s", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if ok && ipnet.IP.To4() == nil && ipnet.IP.IsLinkLocalUnicast() {
				return ipnet.IP.String(), iface.Name
			}
		}
	}

	t.Skip("no link-local IPv6 address on this host")

	return "", ""
}

func splitTestServer(t *testing.T, srv *httptest.Server) (string, int) {
	t.Helper()

	addr := srv.Listener.Addr().(*net.TCPAddr)

	return addr.IP.String(), addr.Port
}
