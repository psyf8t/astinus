package telemetry

import (
	"regexp"
	"testing"
)

// TestEventsAllConstantsUnique guarantees no two event constants
// share a value. A duplicate is almost always a copy-paste accident
// and would corrupt downstream dashboards filtering on `msg`.
func TestEventsAllConstantsUnique(t *testing.T) {
	seen := make(map[string]int, len(AllEvents))
	for _, e := range AllEvents {
		seen[e]++
	}
	for v, count := range seen {
		if count > 1 {
			t.Errorf("event %q appears %d times in AllEvents", v, count)
		}
	}
}

// TestEventsStringFormat enforces the documented
// `<subsystem>.<action>[.<state>]` shape so log-aggregation tooling
// can do prefix-grouped queries reliably.
func TestEventsStringFormat(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`)
	for _, e := range AllEvents {
		if !pattern.MatchString(e) {
			t.Errorf("event %q does not match %s", e, pattern)
		}
	}
}

// TestEventsAllNonEmpty guards against an accidental ""-valued
// constant slipping into the slice.
func TestEventsAllNonEmpty(t *testing.T) {
	for i, e := range AllEvents {
		if e == "" {
			t.Errorf("AllEvents[%d] is empty", i)
		}
	}
}
