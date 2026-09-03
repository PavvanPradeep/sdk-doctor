package cmd

import (
	"strings"
	"testing"

	"github.com/couchbaselabs/sdk-doctor/helpers"
)

func attempt(kind, endpoint string, phase helpers.Phase, category helpers.Category) helpers.Attempt {
	return helpers.Attempt{
		Kind:     kind,
		Endpoint: endpoint,
		Phase:    string(phase),
		Category: string(category),
		Elapsed:  "3ms",
	}
}

const legacyUnreachable = "All endpoints specified by your connection string were unreachable," +
	" further cluster diagnostics are not possible"

func TestBootstrapSummaryKeepsTheLegacyLineWhenNothingAnswered(t *testing.T) {
	tests := []struct {
		name     string
		attempts []helpers.Attempt
	}{
		{
			"every endpoint refused",
			[]helpers.Attempt{
				attempt("bootstrap-cccp", "node1:11210", helpers.PhaseTCP, helpers.CategoryTCPRefused),
				attempt("bootstrap-http-terse", "node1:8091", helpers.PhaseTCP, helpers.CategoryTCPRefused),
			},
		},
		{
			"every endpoint filtered",
			[]helpers.Attempt{
				attempt("bootstrap-cccp", "node1:11210", helpers.PhaseTCP, helpers.CategoryTCPTimeout),
			},
		},
		{
			"nothing resolved",
			[]helpers.Attempt{
				attempt("bootstrap-cccp", "nope.invalid:11210", helpers.PhaseDNS, helpers.CategoryDNSNXDomain),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := bootstrapSummary(test.attempts, "travel"); got != legacyUnreachable {
				t.Errorf("expected the legacy sentence verbatim, got:\n%s", got)
			}
		})
	}
}

func TestBootstrapSummaryNamesTheCauseWhenSomethingAnswered(t *testing.T) {
	tests := []struct {
		name     string
		attempts []helpers.Attempt
		contains string
		excludes string
	}{
		{
			name: "authentication rejected",
			attempts: []helpers.Attempt{
				attempt("bootstrap-cccp", "node1:11210", helpers.PhaseSASL, helpers.CategoryAuthRejected),
				attempt("bootstrap-http-terse", "node1:8091", helpers.PhaseResponse, helpers.CategoryAuthRejected),
			},
			contains: "Authentication was rejected by 2 of 2 endpoints",
			excludes: "unreachable",
		},
		{
			name: "missing bucket",
			attempts: []helpers.Attempt{
				attempt("bootstrap-cccp", "node1:11210", helpers.PhaseSelectBucket, helpers.CategoryBucketNotFound),
			},
			contains: "`travel` does not exist",
			excludes: "unreachable",
		},
		{
			name: "rejected certificate",
			attempts: []helpers.Attempt{
				attempt("bootstrap-cccp", "node1:11207", helpers.PhaseTLS, helpers.CategoryTLSVerify),
			},
			contains: "certificate",
			excludes: "unreachable",
		},
		{
			name: "unusable configuration",
			attempts: []helpers.Attempt{
				attempt("bootstrap-http-terse", "node1:8091", helpers.PhaseConfig, helpers.CategoryConfigInvalid),
			},
			contains: "could not use",
			excludes: "unreachable",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := bootstrapSummary(test.attempts, "travel")

			if !strings.Contains(got, test.contains) {
				t.Errorf("expected %q in:\n%s", test.contains, got)
			}
			if strings.Contains(got, test.excludes) {
				t.Errorf("did not expect %q in:\n%s", test.excludes, got)
			}
		})
	}
}

func TestBootstrapSummaryScopesTheReachableClauseToItsOwnEndpoints(t *testing.T) {
	// Fix 1: the "reachable" clause must be scoped to the endpoints the category
	//  actually describes ("those endpoints"), not phrased as a blanket claim about
	//  every endpoint in the run ("the endpoints themselves" / "the endpoints"), which
	//  would contradict a "N of M" count that is less than the total.
	tests := []struct {
		name     string
		attempts []helpers.Attempt
	}{
		{
			"auth rejected on some endpoints",
			[]helpers.Attempt{
				attempt("bootstrap-cccp", "node1:11210", helpers.PhaseSASL, helpers.CategoryAuthRejected),
				attempt("bootstrap-cccp", "node2:11210", helpers.PhaseTCP, helpers.CategoryTCPTimeout),
			},
		},
		{
			"bucket not found",
			[]helpers.Attempt{
				attempt("bootstrap-cccp", "node1:11210", helpers.PhaseSelectBucket, helpers.CategoryBucketNotFound),
			},
		},
		{
			"tls verify rejected on some endpoints",
			[]helpers.Attempt{
				attempt("bootstrap-cccp", "node1:11207", helpers.PhaseTLS, helpers.CategoryTLSVerify),
				attempt("bootstrap-cccp", "node2:11207", helpers.PhaseTCP, helpers.CategoryTCPTimeout),
			},
		},
		{
			"tls handshake failed on some endpoints",
			[]helpers.Attempt{
				attempt("bootstrap-cccp", "node1:11207", helpers.PhaseTLS, helpers.CategoryTLSHandshake),
				attempt("bootstrap-cccp", "node2:11207", helpers.PhaseTCP, helpers.CategoryTCPTimeout),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := bootstrapSummary(test.attempts, "travel")

			if !strings.Contains(got, "those endpoints were reachable") {
				t.Errorf("expected the scoped 'those endpoints were reachable' clause in:\n%s", got)
			}
			if strings.Contains(got, "the endpoints themselves were reachable") {
				t.Errorf("did not expect the unscoped 'the endpoints themselves were reachable' clause in:\n%s", got)
			}
			if strings.Contains(got, "the endpoints were reachable") {
				t.Errorf("did not expect the unscoped 'the endpoints were reachable' clause in:\n%s", got)
			}
		})
	}
}

func TestBootstrapSummaryRanksAuthAboveAnUnreachableNode(t *testing.T) {
	attempts := []helpers.Attempt{
		attempt("bootstrap-cccp", "node1:11210", helpers.PhaseTCP, helpers.CategoryTCPTimeout),
		attempt("bootstrap-cccp", "node2:11210", helpers.PhaseSASL, helpers.CategoryAuthRejected),
	}

	got := bootstrapSummary(attempts, "travel")

	if !strings.Contains(got, "Authentication was rejected by 1 of 2 endpoints") {
		t.Errorf("expected the auth rejection to lead, got:\n%s", got)
	}

	// Nothing is hidden: the secondary cause is named too
	if !strings.Contains(got, "tcp_timeout") {
		t.Errorf("expected the secondary category to be named, got:\n%s", got)
	}
}

func TestBootstrapSummaryFallsBackToTheRawError(t *testing.T) {
	// This attempt got past TCP (PhaseConfig), so rule 1 does not apply and the legacy
	//  "unreachable" sentence would be false here — the default branch must say something
	//  else while still carrying the raw error through.
	odd := attempt("bootstrap-cccp", "node1:11210", helpers.PhaseConfig, helpers.CategoryUnknown)
	odd.Error = "something nobody predicted"

	got := bootstrapSummary([]helpers.Attempt{odd}, "travel")

	if strings.Contains(got, "unreachable") {
		t.Errorf("did not expect the legacy 'unreachable' wording for a post-TCP failure, got:\n%s", got)
	}
	if !strings.Contains(got, "something nobody predicted") {
		t.Errorf("expected the raw error to be carried through, got:\n%s", got)
	}
}

func TestBootstrapSummaryKeepsTheLegacyLineOnlyWhenNothingGotPastTCP(t *testing.T) {
	// Fix 4: rule 1 (reachedPastTCP) must be the only path that emits the legacy
	//  sentence. This input carries a Phase of PhaseTCP (so reachedPastTCP is false) and
	//  a Category of CategoryUnknown with a non-empty Error, which is exactly the
	//  shape that also flows through the switch's default branch when reachedPastTCP is
	//  (incorrectly) true. If rule 1 is bypassed, the default branch produces a
	//  different, non-legacy message, so this test distinguishes the two paths.
	odd := attempt("bootstrap-cccp", "node1:11210", helpers.PhaseTCP, helpers.CategoryUnknown)
	odd.Error = "something nobody predicted"

	got := bootstrapSummary([]helpers.Attempt{odd}, "travel")

	if got != legacyUnreachable {
		t.Errorf("expected the legacy sentence verbatim when nothing got past TCP, got:\n%s", got)
	}
}

func TestRenderAttemptTableAlignsAndCoversEveryAttempt(t *testing.T) {
	// Endpoints (and phases, and elapsed times) of clearly different lengths, and
	//  deliberately not matching the header words' own lengths, so that a column which
	//  lost its fixed-width padding would visibly misalign rather than align by
	//  coincidence.
	attempts := []helpers.Attempt{
		attempt("bootstrap-cccp", "e1:1", helpers.PhaseSASL, helpers.CategoryAuthRejected),
		attempt("bootstrap-http-terse", "node1.sdkdoctor.test.example.com:8091", helpers.PhaseResponse, helpers.CategoryAuthRejected),
	}
	attempts[0].Elapsed = "3ms"
	attempts[1].Elapsed = "1500ms"

	got := renderAttemptTable(attempts)

	for _, want := range []string{
		"ENDPOINT", "PHASE", "ELAPSED", "RESULT",
		"e1:1", "node1.sdkdoctor.test.example.com:8091",
		"sasl", "response", "authentication_rejected",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in the table:\n%s", want, got)
		}
	}

	// One header plus one row per attempt
	if lines := strings.Count(strings.TrimSpace(got), "\n"); lines != 2 {
		t.Errorf("expected 3 lines for 2 attempts, got %d:\n%s", lines+1, got)
	}

	// Trim only the trailing newline here (unlike the count check above) so each
	//  line keeps its leading padding intact - trimming the whole string would strip
	//  the header's leading spaces but not the rows', skewing every offset below.
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d:\n%s", len(lines), got)
	}
	header, row1, row2 := lines[0], lines[1], lines[2]

	// Real alignment check: the byte offset of each left-justified/unpadded column's
	//  first character must be identical across the header and every row. ENDPOINT and
	//  PHASE are left-justified (%-Ns) and RESULT is the trailing unpadded column
	//  (%s); each one's start offset depends on every column before it being padded to
	//  its declared fixed width, so swapping any of those specs for a bare %s would
	//  shift these offsets apart for rows of different lengths.
	columns := map[string][]int{
		"ENDPOINT": {
			strings.Index(header, "ENDPOINT"),
			strings.Index(row1, "e1:1"),
			strings.Index(row2, "node1.sdkdoctor.test.example.com:8091"),
		},
		"PHASE": {
			strings.Index(header, "PHASE"),
			strings.Index(row1, "sasl"),
			strings.Index(row2, "response"),
		},
		"RESULT": {
			strings.Index(header, "RESULT"),
			strings.Index(row1, "authentication_rejected"),
			strings.Index(row2, "authentication_rejected"),
		},
	}

	for name, offsets := range columns {
		for _, off := range offsets {
			if off < 0 {
				t.Fatalf("column %s marker not found on every line, offsets: %v\ntable:\n%s", name, offsets, got)
			}
		}
		if offsets[0] != offsets[1] || offsets[1] != offsets[2] {
			t.Errorf("column %s is misaligned: header/row1/row2 offsets = %v\ntable:\n%s", name, offsets, got)
		}
	}
}

func TestReachedPastTCP(t *testing.T) {
	tests := []struct {
		name     string
		attempts []helpers.Attempt
		want     bool
	}{
		{"dns only", []helpers.Attempt{attempt("k", "e", helpers.PhaseDNS, helpers.CategoryDNSNXDomain)}, false},
		{"tcp only", []helpers.Attempt{attempt("k", "e", helpers.PhaseTCP, helpers.CategoryTCPRefused)}, false},
		{"tls counts as past tcp", []helpers.Attempt{attempt("k", "e", helpers.PhaseTLS, helpers.CategoryTLSVerify)}, true},
		{"sasl counts", []helpers.Attempt{attempt("k", "e", helpers.PhaseSASL, helpers.CategoryAuthRejected)}, true},
		{"mixed", []helpers.Attempt{
			attempt("k", "e1", helpers.PhaseTCP, helpers.CategoryTCPRefused),
			attempt("k", "e2", helpers.PhaseSASL, helpers.CategoryAuthRejected),
		}, true},
		{"no attempts", nil, false},
	}

	for _, test := range tests {
		if got := reachedPastTCP(test.attempts); got != test.want {
			t.Errorf("%s: got %t, want %t", test.name, got, test.want)
		}
	}
}

// markAttemptCategory must amend only the endpoint it names. A host bootstrapped over
// both CCCP and HTTP produces two attempts sharing a hostname on different ports; a
// match keyed on the endpoint's host alone would stamp both, mislabeling whichever one
// actually succeeded.
func TestMarkAttemptCategoryLeavesAnUnrelatedEndpointAlone(t *testing.T) {
	gReport = diagnosticReport{}
	gReport.Attempts = []helpers.Attempt{
		attempt("bootstrap-cccp", "hostA:11210", helpers.PhaseConfig, ""),
		attempt("bootstrap-http-terse", "hostA:8091", helpers.PhaseResponse, ""),
	}

	markAttemptCategory("hostA:8091", helpers.CategoryConfigEmpty)

	if got := gReport.Attempts[0].Category; got != "" {
		t.Errorf("unrelated endpoint hostA:11210 was amended: category = %q, want empty", got)
	}
	if got := gReport.Attempts[1].Category; got != string(helpers.CategoryConfigEmpty) {
		t.Errorf("named endpoint hostA:8091 was not amended: category = %q, want %q", got, helpers.CategoryConfigEmpty)
	}
}
