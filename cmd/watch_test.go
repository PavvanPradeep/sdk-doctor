package cmd

import (
	"errors"
	"testing"
	"time"

	"github.com/couchbaselabs/sdk-doctor/helpers"
)

func TestFormatWatchRowSuccess(t *testing.T) {
	at := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	counters := helpers.TCPCounters{
		RTT: 1500 * time.Microsecond, RTTVar: 250 * time.Microsecond,
		CongestionWindow: 10, TotalRetransmits: 3, Lost: 1,
	}

	row := formatWatchRow(at, "node1", 11210, counters, true, nil)

	want := []string{"2026-08-27T12:00:00Z", "node1", "11210", "1.500", "0.250", "10", "3", "1", ""}
	if len(row) != len(want) {
		t.Fatalf("got %d columns, want %d: %v", len(row), len(want), row)
	}
	for i := range want {
		if row[i] != want[i] {
			t.Errorf("column %d = %q, want %q", i, row[i], want[i])
		}
	}
}

func TestFormatWatchRowNoCounters(t *testing.T) {
	at := time.Now()

	row := formatWatchRow(at, "node1", 11210, helpers.TCPCounters{}, false, nil)

	for i, col := range row[3:8] {
		if col != "" {
			t.Errorf("counter column %d = %q, want empty when unsupported", i+3, col)
		}
	}
}

func TestFormatWatchRowPingError(t *testing.T) {
	at := time.Now()

	row := formatWatchRow(at, "node1", 11210, helpers.TCPCounters{}, true, errors.New("connection reset"))

	if got := row[len(row)-1]; got != "connection reset" {
		t.Errorf("error column = %q, want %q", got, "connection reset")
	}
}
