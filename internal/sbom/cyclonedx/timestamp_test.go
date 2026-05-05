package cyclonedx

import "testing"

func TestParseTimestamp(t *testing.T) {
	cases := []string{
		"2026-04-30T10:15:30Z",
		"2026-04-30T10:15:30.123456789Z",
		"2026-04-30T10:15:30+02:00",
		"2026-04-30T10:15:30",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			got, err := parseTimestamp(in)
			if err != nil {
				t.Fatalf("parseTimestamp(%q): %v", in, err)
			}
			if got.IsZero() {
				t.Fatalf("parseTimestamp(%q) returned zero time", in)
			}
		})
	}
}

func TestParseTimestampRejectsGarbage(t *testing.T) {
	if _, err := parseTimestamp("not a timestamp"); err == nil {
		t.Fatal("expected error for unparseable timestamp")
	}
}
