package cpe

import (
	"context"
	"testing"
	"time"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// timeoutAwareResolver implements the Timeouts() reporter the
// enricher's resolverTimeouts() helper type-asserts on. The
// production MultiSourceResolver provides this; this test uses
// a stub so we don't bring sources/ into the cpe package's tests.
type timeoutAwareResolver struct {
	perSource, perCall time.Duration
}

func (r *timeoutAwareResolver) Resolve(_ PURL) []Candidate { return nil }
func (r *timeoutAwareResolver) Timeouts() (time.Duration, time.Duration) {
	return r.perSource, r.perCall
}

// TestEnricher_StampsConfiguredTimeouts — S8 Task 0. Every Enrich
// call stamps the operator-supplied wall-time bounds on SBOM
// metadata so when total-cap-hit fires, the operator reads BOTH
// the elapsed wall-time AND the cap that produced the trip
// without cross-referencing the CLI invocation. ADR-0057
// amendment.
func TestEnricher_StampsConfiguredTimeouts(t *testing.T) {
	res := &timeoutAwareResolver{
		perSource: 45 * time.Second,
		perCall:   7 * time.Second,
	}
	e := NewWithResolver(res).WithTotalCap(2 * time.Minute)

	sbom := &model.SBOM{Components: []model.Component{{Name: "x"}}}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	cases := []struct {
		key  string
		want string
	}{
		{model.PropertyCPETotalCapConfigured, "2m0s"},
		{model.PropertyCPESourceTimeoutConfigured, "45s"},
		{model.PropertyCPECallTimeoutConfigured, "7s"},
	}
	for _, c := range cases {
		got := sbom.Metadata.Properties[c.key]
		if got != c.want {
			t.Errorf("%s = %q, want %q", c.key, got, c.want)
		}
	}
}

// TestStampConfiguredTimeouts_ZeroSkipsKey — defensive. A resolver
// constructed without timeouts (legacy / tests) returns (0, 0)
// from Timeouts(); the stamp must delete (or omit) the affected
// keys rather than writing "0s" — operators reading the SBOM
// shouldn't see misleading "configured = 0s" values.
func TestStampConfiguredTimeouts_ZeroSkipsKey(t *testing.T) {
	sbom := &model.SBOM{
		Metadata: model.Metadata{
			Properties: map[string]string{
				model.PropertyCPETotalCapConfigured:      "stale-old-value",
				model.PropertyCPESourceTimeoutConfigured: "60s",
				model.PropertyCPECallTimeoutConfigured:   "10s",
			},
		},
	}
	stampConfiguredTimeouts(sbom, 0, 0, 0)
	for _, k := range []string{
		model.PropertyCPETotalCapConfigured,
		model.PropertyCPESourceTimeoutConfigured,
		model.PropertyCPECallTimeoutConfigured,
	} {
		if _, ok := sbom.Metadata.Properties[k]; ok {
			t.Errorf("%s should be deleted on zero input, but exists", k)
		}
	}
}
