package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerdictForStatus(t *testing.T) {
	tests := []struct {
		name           string
		healthEndpoint bool
		status         int
		want           httpProbeVerdict
	}{
		{"no health endpoint", false, 200, probeReachable},
		{"no health endpoint, client error", false, 403, probeReachable},
		{"no health endpoint, server error", false, 500, probeUnhealthy},
		{"healthy", true, 200, probeHealthy},
		{"health endpoint absent", true, 404, probeHealthUntested},
		{"proxied away", true, 302, probeHealthUntested},
		{"credentials rejected", true, 401, probeUnhealthy},
		{"forbidden", true, 403, probeUnhealthy},
		{"service error", true, 503, probeUnhealthy},
	}

	for _, test := range tests {
		if got := verdictForStatus(test.healthEndpoint, test.status); got != test.want {
			t.Errorf("%s: verdictForStatus(%t, %d) = %d, want %d",
				test.name, test.healthEndpoint, test.status, got, test.want)
		}
	}
}

// A wrong path silently stops probing health, and no other test would notice
func TestHealthPathsCoverEveryServiceWithADocumentedEndpoint(t *testing.T) {
	want := map[string]string{
		"mgmt": "/pools",
		"n1ql": "/admin/ping",
		"cbas": "/admin/ping",
		"fts":  "/api/ping",
	}

	for service, path := range want {
		if got := healthPaths[service]; got != path {
			t.Errorf("healthPaths[%q] = %q, want %q", service, got, path)
		}
	}

	if got, ok := healthPaths["capi"]; ok {
		t.Errorf("views has no health endpoint beyond `/`, got %q", got)
	}
}

func TestServiceProbeClientDoesNotFollowRedirects(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("some other service"))
	}))
	defer final.Close()

	proxied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer proxied.Close()

	resp, err := newServiceProbeClient(nil).Get(proxied.URL)
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if got := resp.Header.Get("Location"); got != final.URL {
		t.Errorf("redirect destination = %q, want %q", got, final.URL)
	}
}

func TestBoundedBody(t *testing.T) {
	got := boundedBody(strings.NewReader("  unauthorized\n  check your\tcredentials  "))
	if got != "unauthorized check your credentials" {
		t.Errorf("body = %q, want the whitespace collapsed", got)
	}

	if got := boundedBody(strings.NewReader(strings.Repeat("x", 4096))); len(got) != maxProbeBody {
		t.Errorf("body length = %d, want it bounded at %d", len(got), maxProbeBody)
	}
}
