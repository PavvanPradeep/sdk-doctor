package helpers

import (
	"errors"
	"testing"
	"time"
)

func ms(values ...int) []time.Duration {
	out := make([]time.Duration, 0, len(values))
	for _, v := range values {
		out = append(out, time.Duration(v)*time.Millisecond)
	}

	return out
}

func withSamples(values ...int) *PingHelper {
	samples := ms(values...)

	return &PingHelper{count: len(samples), samples: samples}
}

func TestStatsOfNothing(t *testing.T) {
	var ph PingHelper
	ph.StopOne(ph.StartOne(), errors.New("fake"))

	if ph.Successes() != 0 || ph.Errors() != 1 || ph.Count() != 1 {
		t.Fatalf("unexpected counts: %d/%d/%d", ph.Successes(), ph.Errors(), ph.Count())
	}

	for name, got := range map[string]time.Duration{
		"min":    ph.Min(),
		"max":    ph.Max(),
		"mean":   ph.Mean(),
		"p99":    ph.Percentile(99),
		"stddev": ph.StdDev(),
	} {
		if got != 0 {
			t.Fatalf("expected zero %s, got %s", name, got)
		}
	}
}

func TestPercentile(t *testing.T) {
	ph := withSamples(3, 10, 1, 7, 5, 2, 9, 4, 8, 6)

	for _, tc := range []struct {
		p    float64
		want int
	}{
		{0, 1},
		{50, 5},
		{90, 9},
		{99, 10},
		{100, 10},
	} {
		if got := ph.Percentile(tc.p); got != time.Duration(tc.want)*time.Millisecond {
			t.Fatalf("p%v: expected %dms, got %s", tc.p, tc.want, got)
		}
	}

	if ph.Min() != time.Millisecond || ph.Max() != 10*time.Millisecond {
		t.Fatalf("min/max wrong: %s/%s", ph.Min(), ph.Max())
	}
	if want := 5500 * time.Microsecond; ph.Mean() != want {
		t.Fatalf("expected mean %s, got %s", want, ph.Mean())
	}
}

func TestStdDev(t *testing.T) {
	got := withSamples(1, 2, 3, 4, 5, 6, 7, 8, 9, 10).StdDev()

	if diff := got - 2872281*time.Nanosecond; diff > time.Microsecond || diff < -time.Microsecond {
		t.Fatalf("expected ~2.872ms stddev, got %s", got)
	}

	if got := withSamples(5).StdDev(); got != 0 {
		t.Fatalf("expected zero stddev for one sample, got %s", got)
	}
}

func TestRTOSuspects(t *testing.T) {
	fast := []int{2, 2, 2, 2, 2, 2, 2, 2, 2, 2}

	loss := append([]int{816, 204, 408}, fast...)
	got := RTOSuspects(ms(loss...))

	want := ms(204, 408, 816)
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}

	if got := RTOSuspects(ms(append([]int{300}, fast...)...)); got != nil {
		t.Fatalf("300ms is not an RTO multiple, got %v", got)
	}

	slow := ms(190, 195, 200, 205, 198, 202, 191, 209, 197, 203)
	if got := RTOSuspects(slow); got != nil {
		t.Fatalf("slow link should not be flagged as loss, got %v", got)
	}

	if got := RTOSuspects(ms(2, 204)); got != nil {
		t.Fatalf("expected nil for a tiny sample, got %v", got)
	}
}

func TestPercentile99IsMaxBelow100Samples(t *testing.T) {
	ascending := func(n int) *PingHelper {
		values := make([]int, n)
		for i := range values {
			values[i] = i + 1
		}

		return withSamples(values...)
	}

	for n := 1; n < 100; n++ {
		if ph := ascending(n); ph.Percentile(99) != ph.Max() {
			t.Fatalf("n=%d: p99 %s should equal max %s", n, ph.Percentile(99), ph.Max())
		}
	}

	if ph := ascending(100); ph.Percentile(99) == ph.Max() {
		t.Fatalf("n=100: p99 should have diverged from max")
	}
}
