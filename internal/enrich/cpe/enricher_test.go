package cpe

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestEnrichKnownPURLBundled(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{
			{Name: "express", PURL: "pkg:npm/express@4.18.2"},
		},
	}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	if len(c.CPEs) != 1 {
		t.Fatalf("CPEs = %v", c.CPEs)
	}
	if c.CPEs[0] != "cpe:2.3:a:expressjs:express:4.18.2:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %q", c.CPEs[0])
	}
	if c.Properties["astinus:cpe:source"] != "bundled" {
		t.Errorf("source = %q", c.Properties["astinus:cpe:source"])
	}
	// Sprint 3 Task 0: confidence is now a numeric stamp ("0.95"
	// for bundled / curated hits) instead of the legacy "high" /
	// "low" labels. ADR-0029.
	if c.Properties["astinus:cpe:confidence"] != "0.95" {
		t.Errorf("confidence = %q", c.Properties["astinus:cpe:confidence"])
	}
}

func TestEnrichUnknownPURLHeuristic(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{
			{Name: "rare", PURL: "pkg:gem/rare-thing@1.0"},
		},
	}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	if len(c.CPEs) != 1 {
		t.Fatalf("CPEs = %v", c.CPEs)
	}
	if c.Properties["astinus:cpe:source"] != "heuristic" {
		t.Errorf("source = %q", c.Properties["astinus:cpe:source"])
	}
	// Heuristic guesses now score ConfidenceMedium = 0.70 — at the
	// PrimaryMin floor so they remain primary when no curated source
	// has anything better. ADR-0029.
	if c.Properties["astinus:cpe:confidence"] != "0.70" {
		t.Errorf("confidence = %q", c.Properties["astinus:cpe:confidence"])
	}
}

// TestEnrichPreservesExistingCPEAndPromotesBundledToPrimary —
// post-S3-Task-0 successor of TestEnrichPreservesExistingCPEAndAppendsResolverMatch.
//
// When a Component already carries a CPE (typical: Syft fills every
// component with a placeholder vendor=name CPE), the enricher must
//   - elect the higher-confidence resolver match as the primary `cpe`,
//   - retain the placeholder as `astinus:cpe:alternative:N` so the
//     original input data is not silently lost,
//   - stamp `astinus:cpe:validated = true` so downstream consumers
//     can tell we've checked the input.
//
// The previous schema (one slice in c.CPEs holding both) was the
// vector for the v0.2 false-positive bug — vulnerability scanners
// pulled in any CPE in the slice as authoritative.
func TestEnrichPreservesExistingCPEAndPromotesBundledToPrimary(t *testing.T) {
	preset := "cpe:2.3:a:custom:thing:1.0:*:*:*:*:*:*:*"
	sbom := &model.SBOM{
		Components: []model.Component{
			{Name: "x", PURL: "pkg:npm/express@4", CPEs: []string{preset}},
		},
	}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	if len(c.CPEs) != 1 {
		t.Fatalf("CPEs = %v, want exactly one (primary only)", c.CPEs)
	}
	if c.CPEs[0] == preset {
		t.Errorf("primary CPE should be the bundled hit, not the placeholder: %v", c.CPEs)
	}
	// Preset must survive as an alternative.
	foundAlt := false
	for k, v := range c.Properties {
		if strings.HasPrefix(k, "astinus:cpe:alternative:") &&
			!strings.HasSuffix(k, ":source") &&
			!strings.HasSuffix(k, ":confidence") &&
			v == preset {
			foundAlt = true
		}
	}
	if !foundAlt {
		t.Errorf("preset CPE was not retained as alternative: %v", c.Properties)
	}
	if c.Properties["astinus:cpe:validated"] != "true" {
		t.Errorf("validated stamp = %q", c.Properties["astinus:cpe:validated"])
	}
	if c.Properties["astinus:cpe:source"] != "bundled" {
		t.Errorf("primary source = %q, want bundled", c.Properties["astinus:cpe:source"])
	}
}

// TestEnrichBundledCPEWinsOverSyftPlaceholder — exercises the
// canonical Syft pattern: every component has a placeholder
// `cpe:2.3:a:log4j-core:log4j-core:...` from Syft AND a PURL whose
// bundled mapping resolves to the canonical apache:log4j CPE. The
// bundled answer must become primary; the placeholder lands as an
// alternative.
func TestEnrichBundledCPEWinsOverSyftPlaceholder(t *testing.T) {
	syftPlaceholder := "cpe:2.3:a:log4j-core:log4j-core:2.14.1:*:*:*:*:*:*:*"
	sbom := &model.SBOM{Components: []model.Component{{
		Name:    "log4j-core",
		Version: "2.14.1",
		PURL:    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		CPEs:    []string{syftPlaceholder},
	}}}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	want := "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
	if len(c.CPEs) != 1 || c.CPEs[0] != want {
		t.Errorf("primary CPEs = %v, want [%q]", c.CPEs, want)
	}
	if c.Properties["astinus:cpe:source"] != "bundled" {
		t.Errorf("source = %q, want bundled", c.Properties["astinus:cpe:source"])
	}
	if c.Properties["astinus:cpe:confidence"] != "0.95" {
		t.Errorf("confidence = %q, want 0.95", c.Properties["astinus:cpe:confidence"])
	}
}

// TestEnrichStatsLogged — the cpe.complete log line is the operator's
// debug surface. Verify the counters match expected categories.
func TestEnrichStatsLogged(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	sbom := &model.SBOM{Components: []model.Component{
		{Name: "with-purl", PURL: "pkg:npm/express@4"},                      // no CPE → resolver adds, addedCPE=1
		{Name: "with-cpe", CPEs: []string{"cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}}, // hadCPEAlready=1, no PURL
		{Name: "no-purl-no-cpe"},                                            // noPURL=1
		{Name: "bad-purl", PURL: "not-a-purl"},                              // purlError=1
	}}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"msg":"cpe.complete"`) {
		t.Errorf("missing cpe.complete log: %s", out)
	}
	if !strings.Contains(out, `"components_examined":4`) {
		t.Errorf("examined count wrong: %s", out)
	}
	if !strings.Contains(out, `"had_cpe_already":1`) {
		t.Errorf("had_cpe_already count wrong: %s", out)
	}
	if !strings.Contains(out, `"added_cpe":1`) {
		t.Errorf("added_cpe count wrong: %s", out)
	}
}

// TestEnrichValidatesAndDropsInvalidExisting — invalid CPE strings
// no longer survive in `c.CPEs` (they get classified as rejected
// candidates), and a valid resolver match is elected primary.
func TestEnrichValidatesAndDropsInvalidExisting(t *testing.T) {
	good := "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
	bad := "not a cpe"
	sbom := &model.SBOM{
		Components: []model.Component{
			{Name: "x", PURL: "pkg:npm/x@1", CPEs: []string{good, bad}},
		},
	}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	for _, cpeStr := range c.CPEs {
		if cpeStr == bad {
			t.Errorf("invalid CPE was kept in primary set: %v", c.CPEs)
		}
	}
	if c.Properties["astinus:cpe:validated"] != "partial" {
		t.Errorf("validated stamp = %q", c.Properties["astinus:cpe:validated"])
	}
}

func TestEnrichAllInvalidExisting(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{
			{Name: "x", PURL: "pkg:npm/x@1", CPEs: []string{"not a cpe"}},
		},
	}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	if c.Properties["astinus:cpe:validated"] != "false" {
		t.Errorf("validated = %q", c.Properties["astinus:cpe:validated"])
	}
	if c.Properties["astinus:cpe:invalid"] != "true" {
		t.Errorf("invalid stamp = %q", c.Properties["astinus:cpe:invalid"])
	}
}

func TestEnrichSkipsComponentsWithoutPURL(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{Name: "anonymous"}},
	}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	if len(c.CPEs) != 0 {
		t.Errorf("CPEs should remain empty: %v", c.CPEs)
	}
	if c.Properties != nil {
		t.Errorf("no properties should be set: %v", c.Properties)
	}
}

func TestEnrichLeavesBreadcrumbForBadPURL(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{Name: "x", PURL: "definitely not a purl"}},
	}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	if c.Properties["astinus:cpe:purl-error"] == "" {
		t.Errorf("expected purl-error breadcrumb, got %v", c.Properties)
	}
}

func TestEnrichRecursesIntoSubComponents(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			Name: "outer",
			SubComponents: []model.Component{
				{Name: "child", PURL: "pkg:npm/express@4"},
			},
		}},
	}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components[0].SubComponents[0].CPEs) != 1 {
		t.Errorf("subcomponent CPE missing")
	}
}

func TestEnricherName(t *testing.T) {
	if New().Name() != Name {
		t.Errorf("Name = %q", New().Name())
	}
}

func TestEnrichNilSBOM(t *testing.T) {
	if err := New().Enrich(context.Background(), nil, nil); err == nil {
		t.Fatal("expected error for nil sbom")
	}
}

func TestEnrichIdempotent(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{Name: "x", PURL: "pkg:npm/express@4.18.2"}},
	}
	e := New()
	_ = e.Enrich(context.Background(), sbom, nil)
	first := append([]string{}, sbom.Components[0].CPEs...)
	_ = e.Enrich(context.Background(), sbom, nil)
	if len(sbom.Components[0].CPEs) != len(first) {
		t.Errorf("second run added duplicate CPEs: %v", sbom.Components[0].CPEs)
	}
}
