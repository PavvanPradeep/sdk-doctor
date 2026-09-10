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
	defer saveGlobals()()

	gLog = helpers.Logger{}
	gLog.SetOutput(ioutil.Discard)
	gReport = diagnosticReport{ConnectionString: "couchbases://node1"}

	base := time.Now()
	timing := memd.ConnectTiming{
		DNSStart: base,
		DNSDone:  base.Add(2 * time.Millisecond),
		TCPStart: base.Add(2 * time.Millisecond),
		TCPDone:  base.Add(10 * time.Millisecond),
		TLSStart: base.Add(10 * time.Millisecond),
		TLSDone:  base.Add(40 * time.Millisecond),
	}
	logConnectPhases(helpers.NewAttempt("service-kv", "node1:11207", 2000*time.Millisecond).
		WithTiming(timing, 5*time.Millisecond).
		Finish(helpers.PhaseSelectBucket, "", nil), timing)

	gLog.Warn("something looks off")
	gLog.Error("something broke")

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

	// The literal, not the constant: comparing against the same symbol would pin nothing
	if got.SchemaVersion != 1 {
		t.Fatalf("expected schema version 1, got %d", got.SchemaVersion)
	}

	if len(got.Attempts) != 1 {
		t.Fatalf("expected one attempt, got %+v", got.Attempts)
	}

	attempt := got.Attempts[0]
	if attempt.Kind != "service-kv" || attempt.Endpoint != "node1:11207" {
		t.Errorf("unexpected attempt identity: %+v", attempt)
	}
	if attempt.DNS != "2ms" || attempt.TCP != "8ms" || attempt.TLS != "30ms" || attempt.SASL != "5ms" {
		t.Errorf("unexpected phase durations: %+v", attempt)
	}
	if attempt.Category != "" {
		t.Errorf("expected no category on a successful attempt, got %q", attempt.Category)
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
	if got.Summary != (reportSummary{Warnings: 1, Errors: 1, Worst: "ERRO"}) {
		t.Fatalf("unexpected report summary: %+v", got.Summary)
	}
}

func TestLogConnectPhasesWithoutDNSOrTLS(t *testing.T) {
	defer saveGlobals()()

	var out strings.Builder
	gLog = helpers.Logger{}
	gLog.SetOutput(&out)
	gReport = diagnosticReport{}

	base := time.Now()
	timing := memd.ConnectTiming{
		TCPStart: base,
		TCPDone:  base.Add(3 * time.Millisecond),
	}
	logConnectPhases(helpers.NewAttempt("service-kv", "10.0.0.1:11210", 2000*time.Millisecond).
		WithTiming(timing, 0).
		Finish(helpers.PhaseSelectBucket, "", nil), timing)

	if got := gReport.Attempts[0]; got.DNS != "" || got.TLS != "" || got.SASL != "" {
		t.Fatalf("expected only a TCP phase, got %+v", got)
	}

	// The existing log wording is unchanged
	if !strings.Contains(out.String(), "dns -, tcp 3ms") {
		t.Fatalf("expected an unmeasured DNS phase in the log, got %s", out.String())
	}
}

// A reused keep-alive connection has no TCP timing, but must still reach the report
func TestLogConnectPhasesRecordsButDoesNotLogAttemptsWithoutTCP(t *testing.T) {
	defer saveGlobals()()

	var out strings.Builder
	gLog = helpers.Logger{}
	gLog.SetOutput(&out)
	gReport = diagnosticReport{}

	logConnectPhases(helpers.NewAttempt("service-kv", "10.0.0.1:11210", 2000*time.Millisecond).
		Finish(helpers.PhaseNone, "", nil), memd.ConnectTiming{})

	if len(gReport.Attempts) != 1 {
		t.Fatalf("expected the attempt to be recorded even without TCP timing, got %+v", gReport.Attempts)
	}
	if out.String() != "" {
		t.Fatalf("expected no log output when TCP was never measured, got %q", out.String())
	}
}

// The pipeline never rewrites Kind; a caller building the wrong one is out of reach here
func TestLogConnectPhasesPreservesTheAttemptKindVerbatim(t *testing.T) {
	defer saveGlobals()()

	gLog = helpers.Logger{}
	gLog.SetOutput(ioutil.Discard)
	gReport = diagnosticReport{}

	timing := memd.ConnectTiming{
		TCPStart: time.Now(),
		TCPDone:  time.Now().Add(time.Millisecond),
	}
	logConnectPhases(helpers.NewAttempt("service-mgmt", "node1:8091", 2000*time.Millisecond).
		WithTiming(timing, 0).
		Finish(helpers.PhaseResponse, "", nil), timing)

	if len(gReport.Attempts) != 1 {
		t.Fatalf("expected one attempt, got %+v", gReport.Attempts)
	}
	if got := gReport.Attempts[0].Kind; got != "service-mgmt" {
		t.Fatalf("expected Kind to stay the port-label form %q, got %q", "service-mgmt", got)
	}
}
