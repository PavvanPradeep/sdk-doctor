package cmd

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
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
	ports := matrixPorts([]clusterNode{
		{Hostname: "a", Services: map[string]int{"indexAdmin": 9100, "kv": 11210}},
		{Hostname: "b", Services: map[string]int{"projector": 9999, "capi": 0}},
	})

	got := map[int]string{}
	for i, p := range ports {
		got[p.Port] = p.Name

		if i > 0 && ports[i-1].Port >= p.Port {
			t.Fatalf("ports are not sorted/deduped at %d: %+v", i, ports)
		}
	}
	for _, want := range []int{8091, 9100, 9999, 11210} {
		if _, ok := got[want]; !ok {
			t.Fatalf("expected port %d in matrix, got %+v", want, ports)
		}
	}
	if _, ok := got[0]; ok {
		t.Fatalf("zero port should not be probed: %+v", ports)
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
