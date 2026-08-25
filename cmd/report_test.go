package cmd

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/couchbaselabs/sdk-doctor/helpers"
	"github.com/couchbaselabs/sdk-doctor/memd"
)

func TestWriteReportCarriesTheCollectedResults(t *testing.T) {
	gLog = helpers.Logger{}
	gLog.SetOutput(ioutil.Discard)
	gReport = diagnosticReport{ConnectionString: "couchbases://node1"}

	base := time.Now()
	logConnectPhases("node1", 11207, memd.ConnectTiming{
		DNSStart: base,
		DNSDone:  base.Add(2 * time.Millisecond),
		TCPStart: base.Add(2 * time.Millisecond),
		TCPDone:  base.Add(10 * time.Millisecond),
		TLSStart: base.Add(10 * time.Millisecond),
		TLSDone:  base.Add(40 * time.Millisecond),
	}, 5*time.Millisecond)

	gLog.Warn("something looks off")

	path := filepath.Join(t.TempDir(), "report.json")
	if err := writeReport(path); err != nil {
		t.Fatalf("failed to write report: %s", err)
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read report: %s", err)
	}

	var got diagnosticReport
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("report is not valid json: %s\n%s", err, data)
	}

	if got.ConnectionString != "couchbases://node1" || got.FinishedAt.IsZero() {
		t.Fatalf("unexpected report header: %+v", got)
	}

	if len(got.Connects) != 1 {
		t.Fatalf("expected one connect result, got %+v", got.Connects)
	}

	want := connectResult{Host: "node1", Port: 11207, DNS: "2ms", TCP: "8ms", TLS: "30ms", SASL: "5ms"}
	if got.Connects[0] != want {
		t.Fatalf("expected %+v, got %+v", want, got.Connects[0])
	}

	var warned bool
	for _, entry := range got.Log {
		if entry.Level == "WARN" && entry.Message == "something looks off" {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected the warning in the report log, got %+v", got.Log)
	}
}

func TestLogConnectPhasesWithoutDNSOrTLS(t *testing.T) {
	var out strings.Builder
	gLog = helpers.Logger{}
	gLog.SetOutput(&out)
	gReport = diagnosticReport{}

	base := time.Now()
	logConnectPhases("10.0.0.1", 11210, memd.ConnectTiming{
		TCPStart: base,
		TCPDone:  base.Add(3 * time.Millisecond),
	}, 0)

	if got := gReport.Connects[0]; got.DNS != "" || got.TLS != "" || got.SASL != "" {
		t.Fatalf("expected only a TCP phase, got %+v", got)
	}

	if !strings.Contains(out.String(), "dns -, tcp 3ms") {
		t.Fatalf("expected an unmeasured DNS phase in the log, got %s", out.String())
	}
}
