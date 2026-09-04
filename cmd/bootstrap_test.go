package cmd

import (
	"strings"
	"testing"

	"github.com/couchbaselabs/gocbconnstr"
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
	// The "reachable" clause covers only the endpoints counted, or it contradicts an N-of-M count
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

// An unranked category once counted the same attempt as both "answered" and "further"
func TestBootstrapSummaryCountsAnUnrankedCategoryOnceOnly(t *testing.T) {
	attempts := []helpers.Attempt{
		attempt("bootstrap-http-terse", "node1:8091", helpers.PhaseResponse, helpers.CategoryTCPTimeout),
	}

	got := bootstrapSummary(attempts, "travel")

	if !strings.Contains(got, "tcp_timeout") {
		t.Errorf("expected the observed category to be named, got:\n%s", got)
	}
	if strings.Contains(got, "unreachable") {
		t.Errorf("did not expect the legacy 'unreachable' wording, got:\n%s", got)
	}
	if strings.Contains(got, "further") {
		t.Errorf("did not expect 'further' for a run with a single attempt, got:\n%s", got)
	}
}

// Once a category is ranked, the "further endpoint(s)" loop is still wanted
func TestBootstrapSummaryRankedPathStillAppendsFurther(t *testing.T) {
	attempts := []helpers.Attempt{
		attempt("bootstrap-cccp", "node1:11210", helpers.PhaseTCP, helpers.CategoryTCPTimeout),
		attempt("bootstrap-cccp", "node2:11210", helpers.PhaseSASL, helpers.CategoryAuthRejected),
	}

	got := bootstrapSummary(attempts, "travel")

	if !strings.Contains(got, "Authentication was rejected by 1 of 2 endpoints") {
		t.Errorf("expected the ranked cause to lead, got:\n%s", got)
	}
	if !strings.Contains(got, "1 further endpoint(s) failed with tcp_timeout") {
		t.Errorf("expected the unranked category to still be appended as 'further', got:\n%s", got)
	}
}

func TestBootstrapSummaryFallsBackToTheRawError(t *testing.T) {
	// Past TCP, so the legacy sentence would be false and the raw error must come through instead
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
	// This shape also flows through the default branch, so it separates rule 1 from that path
	odd := attempt("bootstrap-cccp", "node1:11210", helpers.PhaseTCP, helpers.CategoryUnknown)
	odd.Error = "something nobody predicted"

	got := bootstrapSummary([]helpers.Attempt{odd}, "travel")

	if got != legacyUnreachable {
		t.Errorf("expected the legacy sentence verbatim when nothing got past TCP, got:\n%s", got)
	}
}

func TestRenderAttemptTableAlignsAndCoversEveryAttempt(t *testing.T) {
	// Widths differ from each other and from the headers, so lost padding cannot align by luck
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

	// Only the trailing newline is trimmed, or the header loses leading spaces the rows keep
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d:\n%s", len(lines), got)
	}
	header, row1, row2 := lines[0], lines[1], lines[2]

	// Each column's start offset must match across header and rows, so all padding must hold
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

// Both fixtures are sealed the way a real success is, so only the endpoint tells them apart
func TestMarkAttemptCategoryLeavesAnUnrelatedEndpointAlone(t *testing.T) {
	defer saveGlobals()()

	gReport = diagnosticReport{}
	gReport.Attempts = []helpers.Attempt{
		attempt("bootstrap-cccp", "hostA:11210", helpers.PhaseConfig, ""),
		attempt("bootstrap-http-terse", "hostA:8091", helpers.PhaseConfig, ""),
	}

	markAttemptCategory("hostA:8091", helpers.CategoryConfigEmpty)

	if got := gReport.Attempts[0].Category; got != "" {
		t.Errorf("unrelated endpoint hostA:11210 was amended: category = %q, want empty", got)
	}
	if got := gReport.Attempts[1].Category; got != string(helpers.CategoryConfigEmpty) {
		t.Errorf("named endpoint hostA:8091 was not amended: category = %q, want %q", got, helpers.CategoryConfigEmpty)
	}
}

// The first fixture is a failure with no cause named, which an empty-category match would stamp
func TestMarkAttemptCategoryOnlyAmendsASuccessfulFetch(t *testing.T) {
	defer saveGlobals()()

	gReport = diagnosticReport{}
	gReport.Attempts = []helpers.Attempt{
		attempt("bootstrap-cccp", "hostA:11210", helpers.PhaseSASL, ""),
		attempt("bootstrap-http-terse", "hostA:11210", helpers.PhaseConfig, ""),
	}

	markAttemptCategory("hostA:11210", helpers.CategoryConfigEmpty)

	if got := gReport.Attempts[0].Category; got != "" {
		t.Errorf("a failed attempt was amended: category = %q, want empty", got)
	}
	if got := gReport.Attempts[1].Category; got != string(helpers.CategoryConfigEmpty) {
		t.Errorf("the successful fetch was not amended: category = %q, want %q",
			got, helpers.CategoryConfigEmpty)
	}
}

// saveGlobals restores the package's log and report globals; used as `defer saveGlobals()()`
func saveGlobals() func() {
	savedLog, savedReport := gLog, gReport

	return func() {
		gLog, gReport = savedLog, savedReport
	}
}

// The rank order is the whole mechanism for leading with the most actionable cause, so it is
// pinned literally here: deriving the expectation from categoryRank itself would pass under any
// reordering of it, which is precisely the regression this guards.
func TestCategoryRankOrdersTheMostActionableCauseFirst(t *testing.T) {
	want := []helpers.Category{
		helpers.CategoryAuthRejected,
		helpers.CategoryBucketForbidden,
		helpers.CategoryBucketNotFound,
		helpers.CategoryTLSVerify,
		helpers.CategoryTLSHandshake,
		helpers.CategoryResponseTimeout,
		helpers.CategoryCCCPUnsupported,
		helpers.CategoryConfigUnavailable,
		helpers.CategoryConfigInvalid,
		helpers.CategoryConfigEmpty,
		helpers.CategoryServerError,
		helpers.CategoryUnknown,
	}

	if len(categoryRank) != len(want) {
		t.Fatalf("categoryRank has %d entries, want %d: %v", len(categoryRank), len(want), categoryRank)
	}

	for i := range want {
		if categoryRank[i] != want[i] {
			t.Errorf("categoryRank[%d] = %q, want %q", i, categoryRank[i], want[i])
		}
	}

	// Unknown must stay last, or it outranks every cause the doctor can actually name
	if categoryRank[len(categoryRank)-1] != helpers.CategoryUnknown {
		t.Errorf("expected %q to rank last, got %q",
			helpers.CategoryUnknown, categoryRank[len(categoryRank)-1])
	}
}

// The live wrong-bucket shape: CCCP reports unknown (the server closes the connection) while
// HTTP names the real cause.  If unknown wins, the headline loses the only actionable fact.
func TestBootstrapSummaryPrefersANamedCauseOverUnknown(t *testing.T) {
	attempts := []helpers.Attempt{
		attempt("bootstrap-cccp", "node1:11210", helpers.PhaseSelectBucket, helpers.CategoryUnknown),
		attempt("bootstrap-http-terse", "node1:8091", helpers.PhaseResponse, helpers.CategoryBucketNotFound),
	}

	got := bootstrapSummary(attempts, "travel")

	if !strings.Contains(got, "Bucket `travel` does not exist") {
		t.Errorf("expected the named cause to lead, got:\n%s", got)
	}

	if strings.Contains(got, "does not recognise") {
		t.Errorf("expected unknown not to lead, got:\n%s", got)
	}
}

// Auth is the most actionable cause there is; nothing may displace it
func TestBootstrapSummaryRanksAuthAboveEveryOtherNamedCause(t *testing.T) {
	for _, other := range categoryRank {
		if other == helpers.CategoryAuthRejected {
			continue
		}

		attempts := []helpers.Attempt{
			attempt("bootstrap-cccp", "node1:11210", helpers.PhaseConfig, other),
			attempt("bootstrap-http-terse", "node1:8091", helpers.PhaseSASL, helpers.CategoryAuthRejected),
		}

		if got := bootstrapSummary(attempts, "travel"); !strings.Contains(got, "Authentication was rejected") {
			t.Errorf("auth did not lead against %q, got:\n%s", other, got)
		}
	}
}

// Two bootstrap hosts can resolve to the same endpoint string (an LB, or a repeated host), so
// markAttemptCategory matching on endpoint alone is only sound because the master is always the
// FIRST config that succeeded.  Here the first config is usable and the second is not: prefer the
// later one and the unusable config's category lands on the earlier, working record.
func TestMarkAttemptCategoryBlamesTheMastersOwnRecordOnADuplicateEndpoint(t *testing.T) {
	defer saveGlobals()()

	gLog = helpers.Logger{}
	gLog.SetOutput(devNull{})
	gReport = diagnosticReport{}
	gReport.Attempts = []helpers.Attempt{
		attempt("bootstrap-http-terse", "lb:8091", helpers.PhaseConfig, ""),
		attempt("bootstrap-http-terse", "lb:8091", helpers.PhaseConfig, ""),
	}

	hosts := []gocbconnstr.Address{{Host: "lb", Port: 8091}, {Host: "lb", Port: 8091}}
	configs := []*terseBucketConfig{
		{UUID: "abc", SourceHost: "lb", SourcePort: 8091,
			NodesExt: []bucketConfigNodeExt{{Hostname: "lb", Services: map[string]int{"kv": 11210}}}},
		{UUID: "abc", SourceHost: "lb", SourcePort: 8091, NodesExt: nil},
	}

	master := scanTerseConfigList(hosts, configs)
	if master == nil {
		t.Fatal("expected the first host's config to be selected")
	}

	if nodes := nodesFromMasterConfig(*master, "default"); len(nodes) != 1 {
		t.Fatalf("expected the usable first config to yield 1 node, got %d", len(nodes))
	}

	// The usable config was chosen, so no record may be blamed for an unusable one
	for i, a := range gReport.Attempts {
		if a.Category != "" {
			t.Errorf("attempt[%d] was blamed with %q though the master config was usable", i, a.Category)
		}
	}
}

// "returned a configuration the doctor could not use" is false when none was returned at all
func TestBootstrapSummarySeparatesAnAbsentConfigFromAnUnusableOne(t *testing.T) {
	absent := bootstrapSummary([]helpers.Attempt{
		attempt("bootstrap-cccp", "node1:11210", helpers.PhaseConfig, helpers.CategoryConfigUnavailable),
	}, "travel")

	if strings.Contains(absent, "returned a configuration") {
		t.Errorf("an absent configuration was described as one that was returned:\n%s", absent)
	}
	if !strings.Contains(absent, "no configuration available for bucket `travel`") {
		t.Errorf("expected the absent configuration to be named, got:\n%s", absent)
	}

	unusable := bootstrapSummary([]helpers.Attempt{
		attempt("bootstrap-http-terse", "node1:8091", helpers.PhaseConfig, helpers.CategoryConfigEmpty),
	}, "travel")

	if !strings.Contains(unusable, "returned a configuration the doctor could not use") {
		t.Errorf("expected the unusable configuration to keep its sentence, got:\n%s", unusable)
	}

	if absent == unusable {
		t.Error("both config faults produced the same sentence")
	}
}
