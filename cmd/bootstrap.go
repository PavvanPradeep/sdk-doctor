package cmd

import (
	"fmt"
	"strings"

	"github.com/couchbaselabs/sdk-doctor/helpers"
)

// legacyUnreachableMessage is preserved verbatim: support tooling greps for it
const legacyUnreachableMessage = "All endpoints specified by your connection string were unreachable," +
	" further cluster diagnostics are not possible"

func recordAttempt(attempt helpers.Attempt) {
	gReport.Attempts = append(gReport.Attempts, attempt)
}

// markAttemptCategory downgrades a config that was fetched successfully but turned out unusable
func markAttemptCategory(endpoint string, category helpers.Category) {
	for i := range gReport.Attempts {
		attempt := &gReport.Attempts[i]

		// A successful fetch is the only record this can honestly amend, so match it positively
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

// reachedPastTCP decides whether "unreachable" is an honest description of the failure
func reachedPastTCP(attempts []helpers.Attempt) bool {
	for _, attempt := range attempts {
		if phasesPastTCP[attempt.Phase] {
			return true
		}
	}

	return false
}

// categoryRank orders causes by how actionable they are, since that is what the reader needs
var categoryRank = []helpers.Category{
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

// otherCategories lists the categories present besides the selected one, so a mixed run hides nothing
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

// bootstrapSummary builds the line printed when no endpoint yielded a configuration
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
	case helpers.CategoryConfigUnavailable:
		summary = fmt.Sprintf(
			"%d of %d endpoints authenticated but had no configuration available for"+
				" bucket `%s`.", hit, total, bucket)
	case helpers.CategoryConfigInvalid, helpers.CategoryConfigEmpty:
		summary = fmt.Sprintf(
			"%d of %d endpoints responded but returned a configuration the doctor could not use.", hit, total)
	case "":
		// Named inline rather than by the loop below, which would double-count them
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

// renderAttemptTable lays the attempts out one per row, for a reader without the JSON report
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
