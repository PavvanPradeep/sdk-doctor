package helpers

import "time"

// TCPCounters holds kernel-reported TCP statistics for a connection
type TCPCounters struct {
	RTT              time.Duration
	RTTVar           time.Duration
	CongestionWindow uint32
	Lost             uint32
	TotalRetransmits uint32
}
