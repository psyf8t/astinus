package lifecycle

import (
	"testing"
	"time"
)

func TestClassifyStatus(t *testing.T) {
	now := time.Date(2026, 5, 4, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		lc   *Lifecycle
		want Status
	}{
		{"nil → unknown", nil, StatusUnknown},
		{"future EOL → active",
			&Lifecycle{
				ReleaseDate:      mustDate("2023-04-18"),
				ActiveSupportEnd: mustDate("2027-10-22"),
				EOL:              mustDate("2029-04-30"),
			},
			StatusActive,
		},
		{"past active-support, future EOL → maintenance",
			&Lifecycle{
				ReleaseDate:      mustDate("2022-04-19"),
				ActiveSupportEnd: mustDate("2023-10-18"),
				EOL:              mustDate("2027-04-30"),
			},
			StatusMaintenance,
		},
		{"past EOL → eol",
			&Lifecycle{
				ReleaseDate: mustDate("2018-04-26"),
				EOL:         mustDate("2024-06-30"),
			},
			StatusEOL,
		},
		{"eol=true bool → eol",
			&Lifecycle{ReleaseDate: mustDate("2020-04-30"), EOLBoolean: "true"},
			StatusEOL,
		},
		{"empty Lifecycle → unknown",
			&Lifecycle{},
			StatusUnknown,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyStatus(c.lc, now); got != c.want {
				t.Errorf("status = %q, want %q", got, c.want)
			}
		})
	}
}

func TestDaysUntilEOL(t *testing.T) {
	now := time.Date(2026, 5, 4, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		lc       *Lifecycle
		wantDays int
		wantOk   bool
	}{
		{"nil", nil, 0, false},
		{"no eol", &Lifecycle{}, 0, false},
		{"100 days ahead",
			&Lifecycle{EOL: now.Add(100 * 24 * time.Hour)},
			100, true,
		},
		{"50 days past",
			&Lifecycle{EOL: now.Add(-50 * 24 * time.Hour)},
			-50, true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotDays, gotOk := DaysUntilEOL(c.lc, now)
			if gotOk != c.wantOk {
				t.Errorf("ok = %v, want %v", gotOk, c.wantOk)
			}
			if gotDays != c.wantDays {
				t.Errorf("days = %d, want %d", gotDays, c.wantDays)
			}
		})
	}
}

func TestModeIsKnown(t *testing.T) {
	cases := map[Mode]bool{
		ModeOnline: true, ModeOffline: true, ModeHybrid: true,
		Mode("garbage"): false, Mode(""): false,
	}
	for m, want := range cases {
		if m.IsKnown() != want {
			t.Errorf("Mode(%q).IsKnown = %v, want %v", string(m), m.IsKnown(), want)
		}
	}
}

func TestModeEffectiveDefaultsToHybrid(t *testing.T) {
	if Mode("").EffectiveMode() != ModeHybrid {
		t.Error("empty Mode should default to hybrid")
	}
	if ModeOnline.EffectiveMode() != ModeOnline {
		t.Error("non-empty Mode should pass through")
	}
}

// mustDate is a tiny test helper for the cycle date constants.
func mustDate(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}
