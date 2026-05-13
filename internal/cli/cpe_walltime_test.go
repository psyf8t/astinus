package cli

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// TestEnrichFlagDefaults_CPEWallTimes pins the operator-visible
// default values for the three S6-T0 wall-time flags. ADR-0057
// calibrated 3m / 60s / 10s for airflow-class images; a future change
// that nudges any of them needs to update this test + the ADR.
func TestEnrichFlagDefaults_CPEWallTimes(t *testing.T) {
	cmd := newEnrichCommand()
	cases := []struct {
		flag     string
		wantSecs float64
	}{
		{"cpe-total-timeout", 180},
		{"cpe-source-timeout", 60},
		{"cpe-call-timeout", 10},
	}
	for _, c := range cases {
		f := cmd.Flags().Lookup(c.flag)
		if f == nil {
			t.Errorf("flag --%s missing", c.flag)
			continue
		}
		d, err := time.ParseDuration(f.DefValue)
		if err != nil {
			t.Errorf("--%s default %q not a duration: %v", c.flag, f.DefValue, err)
			continue
		}
		if d.Seconds() != c.wantSecs {
			t.Errorf("--%s default = %v, want %vs", c.flag, d, c.wantSecs)
		}
	}
}

// TestEnrichFlagDefaults_AlignWithEnricherConstants asserts the CLI
// default values match the enricher's published constants. If
// somebody bumps cpe.DefaultTotalCap without also updating the
// flag's default, operators reading --help and SBOM metadata see
// different values — this trips the gate. S6 Task 0.
func TestEnrichFlagDefaults_AlignWithEnricherConstants(t *testing.T) {
	cmd := newEnrichCommand()
	cases := []struct {
		flag string
		want time.Duration
	}{
		{"cpe-total-timeout", cpe.DefaultTotalCap},
		{"cpe-source-timeout", cpe.DefaultSourceTimeout},
		{"cpe-call-timeout", cpe.DefaultCallTimeout},
	}
	for _, c := range cases {
		f := cmd.Flags().Lookup(c.flag)
		if f == nil {
			t.Fatalf("flag --%s missing", c.flag)
		}
		d, err := time.ParseDuration(f.DefValue)
		if err != nil {
			t.Fatalf("--%s parse: %v", c.flag, err)
		}
		if d != c.want {
			t.Errorf("--%s default = %v, cpe constant = %v (out of sync)",
				c.flag, d, c.want)
		}
	}
}

// TestBuildCPEEnricher_WallTimeOptsPropagate asserts that operator
// flag values flow through buildCPEEnricher into the configured
// resolver + enricher. We can't read the resolver's internal budget
// map directly, so we sanity-check via the configured-log fields.
// S6 Task 0.
func TestBuildCPEEnricher_WallTimeOptsPropagate(t *testing.T) {
	t.Setenv("NVD_API_KEY", "fake-key-for-test")
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	opts := &enrichOptions{
		cpeMode:          "auto",
		cpeTotalTimeout:  90 * time.Second,
		cpeSourceTimeout: 25 * time.Second,
		cpeCallTimeout:   4 * time.Second,
	}
	enr, err := buildCPEEnricher(opts, nil, logger, 10)
	if err != nil {
		t.Fatalf("buildCPEEnricher: %v", err)
	}
	if enr == nil {
		t.Fatal("enricher is nil")
	}
	for _, want := range []string{`"total_cap":90000000000`, `"source_timeout":25000000000`, `"call_timeout":4000000000`} {
		if !strings.Contains(logBuf.String(), want) {
			t.Errorf("configured log missing %q\nlog:\n%s", want, logBuf.String())
		}
	}
}
