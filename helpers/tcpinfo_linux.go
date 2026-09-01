package helpers

import (
	"crypto/tls"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

func tcpCounters(conn net.Conn) (TCPCounters, bool) {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn = tlsConn.NetConn()
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return TCPCounters{}, false
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return TCPCounters{}, false
	}

	var info *unix.TCPInfo
	var getErr error
	err = rawConn.Control(func(fd uintptr) {
		info, getErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	})
	if err != nil || getErr != nil {
		return TCPCounters{}, false
	}

	return TCPCounters{
		RTT:              time.Duration(info.Rtt) * time.Microsecond,
		RTTVar:           time.Duration(info.Rttvar) * time.Microsecond,
		CongestionWindow: info.Snd_cwnd,
		Lost:             info.Lost,
		TotalRetransmits: info.Total_retrans,
	}, true
}
