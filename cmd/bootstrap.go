package cmd

import (
	"fmt"
	"strings"

	"github.com/couchbaselabs/sdk-doctor/helpers"
)

// legacyUnreachableMessage is the sentence sdk-doctor has always printed when nothing
//
//	answered.  It is preserved verbatim: support tooling greps for it, and for the case
//	it describes it is accurate.
const legacyUnreachableMessage = "All endpoints specified by your connection string were unreachable," +
	" further cluster diagnostics are not possible"

// recordAttempt files an attempt in the report
func recordAttempt(attempt helpers.Attempt) {
	gReport.Attempts = append(gReport.Attempts, attempt)
}

// markAttemptCategory downgrades an already-recorded attempt whose configuration turned
//
//	out to be unusable, which is only discovered after the fetch returned successfully.
//	endpoint is matched exactly (not by host prefix) and only a successful config fetch
//	is amended, so a host that appears more than once in the report — the same hostname
//	bootstrapped over both CCCP and HTTP, say — cannot have an unrelated attempt's
//	outcome overwritten by this one's.  Success is identified positively, by the config
//	phase with no category, rather than by an empty category alone: that keeps the match
//	pinned to the one record this can honestly downgrade even if some future path ever
//	seals a failure without naming a cause.
func markAttemptCategory(endpoint string, category helpers.Category) {
	for i := range gReport.Attempts {
		attempt := &gReport.Attempts[i]

		reachedConfig := attempt.Phase == string(helpers.PhaseConfig) && attempt.Category == ""
		if !reachedConfig || attempt.Endpoint != endpoint {
			continue
		}

		attempt.Category = string(category)
		return
	}
}

// phasesPastTCP are the phases that prove an endpoint answered above the network layer
var phasesPastTCP = map[string]bool{
	string(helpers.PhaseTLS):          true,
	string(helpers.PhaseSASL):         true,
	string(helpers.PhaseSelectBucket): true,
	string(helpers.PhaseResponse):     true,
	string(helpers.PhaseConfig):       true,
}

// reachedPastTCP reports whether any attempt got beyond the TCP handshake, which is
//
//	what decides whether "unreachable" is an honest description of the failure
func reachedPastTCP(attempts []helpers.Attempt) bool {
	for _, attempt := range attempts {
		if phasesPastTCP[attempt.Phase] {
			return true
		}
	}

	return false
}

// categoryRank orders causes by how much they tell the reader, most informative first.
//
//	The most informative cause is the actionable one: if one endpoint rejected the
//	credentials and another was refused, wrong credentials is why bootstrap failed.
var categoryRank = []helpers.Category{
	helpers.CategoryAuthRejected,
	helpers.CategoryBucketForbidden,
	helpers.CategoryBucketNotFound,
	helpers.CategoryTLSVerify,
	helpers.CategoryTLSHandshake,
	helpers.CategoryResponseTimeout,
	helpers.CategoryCCCPUnsupported,
	helpers.CategoryConfigInvalid,
	helpers.CategoryConfigEmpty,
	helpers.CategoryServerError,
	helpers.CategoryUnknown,
}

// rankedCategory returns the highest-ranked category present, or "" if none is
func rankedCategory(attempts []helpers.Attempt) helpers.Category {
	present := map[helpers.Category]bool{}
	for _, attempt := range attempts {
		present[helpers.Category(attempt.Category)] = true
	}

	for _, category := range categoryRank {
		if present[category] {
			return category
		}
	}

	return ""
}

// otherCategories lists the categories present besides the selected one, in the order
//
//	they were observed, so a mixed run hides nothing
func otherCategories(attempts []helpers.Attempt, selected helpers.Category) []helpers.Category {
	var others []helpers.Category
	seen := map[helpers.Category]bool{selected: true, "": true}

	for _, attempt := range attempts {
		category := helpers.Category(attempt.Category)
		if seen[category] {
			continue
		}

		seen[category] = true
		others = append(others, category)
	}

	return others
}

func countWithCategory(attempts []helpers.Attempt, category helpers.Category) int {
	var count int
	for _, attempt := range attempts {
		if helpers.Category(attempt.Category) == category {
			count++
		}
	}

	return count
}

// firstError returns the raw error text of the first attempt carrying the category
func firstError(attempts []helpers.Attempt, category helpers.Category) string {
	for _, attempt := range attempts {
		if helpers.Category(attempt.Category) == category && attempt.Error != "" {
			return attempt.Error
		}
	}

	return ""
}

// bootstrapSummary builds the line printed when no endpoint yielded a configuration.
//
//	Phase decides whether the legacy sentence applies; category decides what replaces it.
func bootstrapSummary(attempts []helpers.Attempt, bucket string) string {
	if !reachedPastTCP(attempts) {
		return legacyUnreachableMessage
	}

	selected := rankedCategory(attempts)
	hit := countWithCategory(attempts, selected)
	total := len(attempts)

	var summary string
	switch selected {
	case helpers.CategoryAuthRejected:
		summary = fmt.Sprintf(
			"Authentication was rejected by %d of %d endpoints; those endpoints were"+
				" reachable, so the credentials rather than the network are at fault.", hit, total)
	case helpers.CategoryBucketForbidden:
		summary = fmt.Sprintf(
			"The supplied credentials authenticated but do not have access to bucket `%s`.", bucket)
	case helpers.CategoryBucketNotFound:
		summary = fmt.Sprintf(
			"Bucket `%s` does not exist on this cluster; those endpoints were reachable.", bucket)
	case helpers.CategoryTLSVerify:
		summary = fmt.Sprintf(
			"The server certificate was rejected by %d of %d endpoints; those endpoints were"+
				" reachable, so trust configuration rather than the network is at fault.", hit, total)
	case helpers.CategoryTLSHandshake:
		summary = fmt.Sprintf(
			"The TLS handshake failed on %d of %d endpoints; those endpoints were reachable.", hit, total)
	case helpers.CategoryResponseTimeout:
		summary = fmt.Sprintf(
			"%d of %d endpoints accepted the connection then stopped responding before"+
				" returning a configuration.", hit, total)
	case helpers.CategoryCCCPUnsupported:
		summary = fmt.Sprintf(
			"%d of %d endpoints authenticated but returned no cluster configuration.", hit, total)
	case helpers.CategoryServerError:
		summary = fmt.Sprintf(
			"%d of %d endpoints returned a server error rather than a configuration.", hit, total)
	case helpers.CategoryConfigInvalid, helpers.CategoryConfigEmpty:
		summary = fmt.Sprintf(
			"%d of %d endpoints responded but returned a configuration the doctor could not use.", hit, total)
	case "":
		// Rule 1 already established that something answered above the network layer, so
		//  the legacy "unreachable" sentence would be false here. Nothing ranked is
		//  present, so the categories actually observed are the whole story - naming them
		//  inline (rather than falling through to the "further endpoint(s)" loop below)
		//  keeps every attempt counted exactly once. Without this, categoryRank's "" match
		//  makes countWithCategory(attempts, "") come back 0, so the primary sentence's
		//  implied set would be empty while every real category showed up as "further" -
		//  double-counting the very attempts the primary sentence was supposed to cover.
		summary = fmt.Sprintf("%d endpoint(s) answered but none returned a usable configuration.", total)

		if present := otherCategories(attempts, selected); len(present) > 0 {
			labels := make([]string, 0, len(present))
			for _, category := range present {
				labels = append(labels, string(category))
			}
			summary += fmt.Sprintf("  Causes observed: %s.", strings.Join(labels, ", "))
		}

		return summary
	default:
		summary = fmt.Sprintf(
			"%d of %d endpoints failed after connecting, with a cause the doctor does not recognise.",
			hit, total)
		if raw := firstError(attempts, selected); raw != "" {
			summary += fmt.Sprintf("  The underlying error was: %s", raw)
		}
	}

	for _, other := range otherCategories(attempts, selected) {
		summary += fmt.Sprintf("  %d further endpoint(s) failed with %s.",
			countWithCategory(attempts, other), other)
	}

	return summary
}

// renderAttemptTable lays the attempts out one per row, for the failure path where the
//
//	reader needs the detail without opening the JSON report
func renderAttemptTable(attempts []helpers.Attempt) string {
	endpointWidth := len("ENDPOINT")
	phaseWidth := len("PHASE")
	elapsedWidth := len("ELAPSED")

	for _, attempt := range attempts {
		if len(attempt.Endpoint) > endpointWidth {
			endpointWidth = len(attempt.Endpoint)
		}
		if len(attempt.Phase) > phaseWidth {
			phaseWidth = len(attempt.Phase)
		}
		if len(attempt.Elapsed) > elapsedWidth {
			elapsedWidth = len(attempt.Elapsed)
		}
	}

	var out strings.Builder

	format := fmt.Sprintf("  %%-%ds  %%-%ds  %%%ds  %%s\n", endpointWidth, phaseWidth, elapsedWidth)
	fmt.Fprintf(&out, format, "ENDPOINT", "PHASE", "ELAPSED", "RESULT")

	for _, attempt := range attempts {
		result := attempt.Category
		if result == "" {
			result = "ok"
		}

		fmt.Fprintf(&out, format, attempt.Endpoint, attempt.Phase, attempt.Elapsed, result)
	}

	return out.String()
}
