package helpers

import (
	"net"
	"testing"
)

func TestTCPCountersOnRealSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %s", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %s", err)
	}
	defer conn.Close()

	counters, ok := tcpCounters(conn)
	if !ok {
		t.Fatal("expected tcpCounters to succeed on a real TCP socket")
	}

	// A fresh, idle loopback connection has sent nothing, so these must start at zero
	if counters.TotalRetransmits != 0 {
		t.Errorf("expected zero retransmits on a fresh connection, got %d", counters.TotalRetransmits)
	}
	if counters.CongestionWindow == 0 {
		t.Error("expected a non-zero congestion window on an established connection")
	}
}

func TestTCPCountersRejectsNonTCPConn(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	if _, ok := tcpCounters(client); ok {
		t.Error("expected tcpCounters to fail on a non-TCP net.Conn")
	}
}
