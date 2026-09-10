package helpers

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestLogEntries(t *testing.T) {
	var out bytes.Buffer
	var log Logger
	log.SetOutput(&out)

	log.Log("informative")
	log.Warn("careful")
	log.Error("broken")

	entries := log.Entries()
	if len(entries) != 3 {
		t.Fatalf("expected three entries, got %+v", entries)
	}

	for i, want := range []string{"INFO", "WARN", "ERRO"} {
		if entries[i].Level != want {
			t.Fatalf("expected entry %d at %s, got %+v", i, want, entries[i])
		}
	}

	stamp := strings.Fields(out.String())[0]
	if _, err := time.Parse(time.RFC3339, stamp); err != nil {
		t.Fatalf("expected an RFC3339 timestamp, got `%s` (error: %s)", stamp, err)
	}

	out.Reset()
	log.PrintSummary()

	if !strings.Contains(out.String(), "careful") || !strings.Contains(out.String(), "broken") {
		t.Fatalf("expected the summary to list the warning and the error, got %s", out.String())
	}
	if strings.Contains(out.String(), "informative") {
		t.Fatalf("expected the summary to omit info lines, got %s", out.String())
	}
	if !strings.Contains(out.String(), "Found 1 warning, 1 error, see listing above.") {
		t.Fatalf("expected exact singular counts, got %s", out.String())
	}
}
