package cmd

import (
	"encoding/csv"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/couchbaselabs/sdk-doctor/helpers"
)

type watchTarget struct {
	Host   string
	Port   int
	Client *helpers.MemdClient
}

var watchCSVHeader = []string{
	"timestamp", "host", "port", "rtt_ms", "rttvar_ms", "cwnd", "retransmits", "lost", "error",
}

// formatWatchRow is pure so the CSV shape can be tested without a real connection
func formatWatchRow(at time.Time, host string, port int, counters helpers.TCPCounters, countersOK bool, pingErr error) []string {
	row := []string{at.Format(time.RFC3339), host, strconv.Itoa(port)}

	if countersOK {
		row = append(row,
			strconv.FormatFloat(counters.RTT.Seconds()*1000, 'f', 3, 64),
			strconv.FormatFloat(counters.RTTVar.Seconds()*1000, 'f', 3, 64),
			strconv.FormatUint(uint64(counters.CongestionWindow), 10),
			strconv.FormatUint(uint64(counters.TotalRetransmits), 10),
			strconv.FormatUint(uint64(counters.Lost), 10))
	} else {
		row = append(row, "", "", "", "", "")
	}

	errText := ""
	if pingErr != nil {
		errText = pingErr.Error()
	}

	return append(row, errText)
}

func sampleWatchTarget(target watchTarget, at time.Time) []string {
	pingErr := target.Client.Ping()
	counters, ok := target.Client.TCPCounters()
	return formatWatchRow(at, target.Host, target.Port, counters, ok, pingErr)
}

// runWatch samples every target on interval until watchDuration elapses or the user hits Ctrl-C,
// writing one CSV row per node per tick. A dead connection is never redialed: every tick after a
// failure reports the same error, which is itself the signal support needs.
func runWatch(targets []watchTarget, outPath string, watchDuration, interval time.Duration) {
	if len(targets) == 0 {
		gLog.Warn("No nodes had an open KV connection, nothing to watch")
		return
	}

	f, err := os.Create(outPath)
	if err != nil {
		gLog.Error("Failed to create --watch-out file `%s` (error: %s)", outPath, err)
		return
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if err := w.Write(watchCSVHeader); err != nil {
		gLog.Error("Failed to write to --watch-out file `%s` (error: %s)", outPath, err)
		return
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	deadline := time.Now().Add(watchDuration)

	gLog.Log("Watching %d node(s) for %s, sampling every %s, writing to `%s` (Ctrl-C to stop early)",
		len(targets), dur(watchDuration), dur(interval), outPath)

	// tick reports whether the watch should continue past this row
	tick := func() bool {
		now := time.Now()
		for _, target := range targets {
			w.Write(sampleWatchTarget(target, now))
		}
		w.Flush()

		if err := w.Error(); err != nil {
			gLog.Error("Failed to write to --watch-out file `%s` (error: %s)", outPath, err)
			return false
		}

		return now.Before(deadline)
	}

	for tick() {
		select {
		case <-ticker.C:
		case <-sigCh:
			gLog.Log("Watch interrupted, results so far are saved to `%s`", outPath)
			return
		}
	}

	gLog.Log("Watch period complete, results saved to `%s`", outPath)
}
