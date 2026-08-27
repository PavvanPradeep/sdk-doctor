//go:build !linux
// +build !linux

package helpers

import "net"

func tcpCounters(conn net.Conn) (TCPCounters, bool) {
	return TCPCounters{}, false
}
