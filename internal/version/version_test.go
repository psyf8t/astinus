package version

import (
	"strings"
	"testing"
)

func TestStringContainsFields(t *testing.T) {
	got := String()
	for _, want := range []string{"astinus", Version, Commit, Date} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, want substring %q", got, want)
		}
	}
}

func TestDefaultsAreNonEmpty(t *testing.T) {
	if Version == "" || Commit == "" || Date == "" {
		t.Fatalf("default version metadata must be non-empty: version=%q commit=%q date=%q",
			Version, Commit, Date)
	}
}
