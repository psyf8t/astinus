package policy

import "testing"

func TestSeverityString(t *testing.T) {
	cases := map[Severity]string{
		SeverityCritical: "critical",
		SeverityHigh:     "high",
		SeverityMedium:   "medium",
		SeverityLow:      "low",
		SeverityInfo:     "info",
		Severity(99):     "info", // unknown defaults to info
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", s, got, want)
		}
	}
}

func TestSeverityAtLeast(t *testing.T) {
	cases := []struct {
		s, floor Severity
		want     bool
	}{
		{SeverityCritical, SeverityHigh, true},
		{SeverityHigh, SeverityHigh, true},
		{SeverityMedium, SeverityHigh, false},
		{SeverityLow, SeverityCritical, false},
		{SeverityInfo, SeverityInfo, true},
	}
	for _, tc := range cases {
		if got := tc.s.AtLeast(tc.floor); got != tc.want {
			t.Errorf("%s.AtLeast(%s) = %v, want %v",
				tc.s.String(), tc.floor.String(), got, tc.want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	cases := map[string]struct {
		want Severity
		ok   bool
	}{
		"critical": {SeverityCritical, true},
		"high":     {SeverityHigh, true},
		"medium":   {SeverityMedium, true},
		"low":      {SeverityLow, true},
		"info":     {SeverityInfo, true},
		"":         {SeverityInfo, true},
		"garbage":  {SeverityInfo, false},
	}
	for s, want := range cases {
		got, ok := ParseSeverity(s)
		if got != want.want || ok != want.ok {
			t.Errorf("ParseSeverity(%q) = (%s, %v), want (%s, %v)",
				s, got.String(), ok, want.want.String(), want.ok)
		}
	}
}
