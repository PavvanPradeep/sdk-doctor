package cmd

import (
	"net"
	"strconv"
	"testing"
	"time"
)

func TestGetSourceNodeExt(t *testing.T) {
	// A cluster with no thisNode must report nil rather than panic the caller.
	none := terseBucketConfig{NodesExt: []bucketConfigNodeExt{
		{Hostname: "a"}, {Hostname: "b"},
	}}
	if got := none.GetSourceNodeExt(); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}

	// And when one is present, it must be the flagged node.
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

	// Advertised ports join the documented ones, and a zero port is not a port.
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
	// No coverage for "filtered" - that needs packets actually dropped.
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
