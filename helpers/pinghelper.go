package helpers

import (
	"math"
	"sort"
	"time"
)

// PingHelper provides a helper for the statistics of pinging
type PingHelper struct {
	count      int
	errorCount int
	samples    []time.Duration
}

// PingState represents the state of a single ping
type PingState time.Time

// StartOne starts one ping
func (ph *PingHelper) StartOne() PingState {
	return PingState(time.Now())
}

// StopOne will stop a ping and add it to the statistics
func (ph *PingHelper) StopOne(state PingState, err error) {
	ph.count++

	if err != nil {
		ph.errorCount++
		return
	}

	ph.samples = append(ph.samples, time.Since(time.Time(state)))
}

// Count returns the number of pings performed
func (ph *PingHelper) Count() int {
	return ph.count
}

// Successes returns the number of successful pings
func (ph *PingHelper) Successes() int {
	return len(ph.samples)
}

// Errors returns the number of ping errors
func (ph *PingHelper) Errors() int {
	return ph.errorCount
}

// Samples returns the duration of every successful ping
func (ph *PingHelper) Samples() []time.Duration {
	return ph.samples
}

// Min returns the minimum duration of a ping
func (ph *PingHelper) Min() time.Duration {
	sorted := sortedCopy(ph.samples)
	if len(sorted) == 0 {
		return 0
	}

	return sorted[0]
}

// Max returns the maximum duration of a ping
func (ph *PingHelper) Max() time.Duration {
	sorted := sortedCopy(ph.samples)
	if len(sorted) == 0 {
		return 0
	}

	return sorted[len(sorted)-1]
}

// Mean returns the average duration of the pings
func (ph *PingHelper) Mean() time.Duration {
	if len(ph.samples) == 0 {
		return 0
	}

	var sum time.Duration
	for _, sample := range ph.samples {
		sum += sample
	}

	return sum / time.Duration(len(ph.samples))
}

// Percentile returns the nearest-rank percentile, p in [0, 100]
func (ph *PingHelper) Percentile(p float64) time.Duration {
	sorted := sortedCopy(ph.samples)
	if len(sorted) == 0 {
		return 0
	}

	idx := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}

	return sorted[idx]
}

// StdDev returns the population standard deviation of the successful pings
func (ph *PingHelper) StdDev() time.Duration {
	if len(ph.samples) < 2 {
		return 0
	}

	mean := float64(ph.Mean())

	var sumSquares float64
	for _, sample := range ph.samples {
		diff := float64(sample) - mean
		sumSquares += diff * diff
	}

	return time.Duration(math.Sqrt(sumSquares / float64(len(ph.samples))))
}

// rtoMin is the shortest TCP retransmission timeout; it doubles per retry
const rtoMin = 200 * time.Millisecond

// rtoTolerance covers jitter; bands stay disjoint below 1/3
const rtoTolerance = 0.20

// RTOSuspects returns ascending samples near an RTO multiple, ignoring any
// not well clear of the median so a slow link is not read as packet loss
func RTOSuspects(samples []time.Duration) []time.Duration {
	if len(samples) < 4 {
		return nil
	}

	sorted := sortedCopy(samples)
	median := sorted[len(sorted)/2]

	var out []time.Duration
	for _, sample := range sorted {
		if sample < 4*median {
			continue
		}

		for target := rtoMin; target <= 16*rtoMin; target *= 2 {
			if math.Abs(float64(sample-target)) <= rtoTolerance*float64(target) {
				out = append(out, sample)
				break
			}
		}
	}

	return out
}

func sortedCopy(samples []time.Duration) []time.Duration {
	out := append([]time.Duration(nil), samples...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })

	return out
}
