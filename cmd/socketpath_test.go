package cmd

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/couchbaselabs/sdk-doctor/helpers"
)

func TestFetchHTTPTerseBucketConfigRecordsTheSocketItUsed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"uuid":"abc","nodesExt":[{"thisNode":true,"services":{"kv":11210}}]}`))
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to read the test server address: %s", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to read the test server port: %s", err)
	}

	_, attempt, err := fetchHTTPTerseBucketConfig(host, port, "travel", "Administrator", "password", nil)
	if err != nil {
		t.Fatalf("expected the fetch to succeed: %s", err)
	}

	if len(attempt.Addresses) != 1 {
		t.Fatalf("expected the connected address to be recorded, got %+v", attempt.Addresses)
	}

	address := attempt.Addresses[0]
	if address.Address != srv.Listener.Addr().String() {
		t.Errorf("remote address = %q, want %q", address.Address, srv.Listener.Addr().String())
	}
	if address.Local == "" {
		t.Error("expected the local socket address to be recorded")
	}
	if address.Family != "ipv4" && address.Family != "ipv6" {
		t.Errorf("address family = %q, want an address family", address.Family)
	}
	if address.Error != "" {
		t.Errorf("expected no error on the connected address, got %q", address.Error)
	}
}

func TestSocketPathNamesOnlyTheAddressThatConnected(t *testing.T) {
	got := socketPath(helpers.Attempt{
		Resolved: []string{"::1", "10.1.2.3"},
		Addresses: []helpers.AddressAttempt{
			{Address: "[::1]:11210", Family: "ipv6", Error: "connection refused"},
			{Address: "10.1.2.3:11210", Family: "ipv4", Local: "10.1.4.7:53182", Interface: "en0"},
		},
	})

	for _, want := range []string{"10.1.4.7:53182 -> 10.1.2.3:11210", "ipv4", "via en0", "2 addresses resolved"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in %q", want, got)
		}
	}

	if strings.Contains(got, "::1") {
		t.Errorf("the address that failed must not be reported as the path used: %q", got)
	}
}

func TestSocketPathIsEmptyWithoutAConnectedAddress(t *testing.T) {
	got := socketPath(helpers.Attempt{
		Addresses: []helpers.AddressAttempt{
			{Address: "10.1.2.3:11210", Family: "ipv4", Error: "i/o timeout"},
		},
	})

	if got != "" {
		t.Errorf("expected no socket path, got %q", got)
	}
}
