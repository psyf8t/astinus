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
	if c.Properties["astinus:cpe:confidence"] != "high" {
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
	if c.Properties["astinus:cpe:confidence"] != "low" {
		t.Errorf("confidence = %q", c.Properties["astinus:cpe:confidence"])
	}
}

// TestEnrichPreservesExistingCPEAndAppendsResolverMatch — post-Stage-13
// hardening Task 5: when a component already has CPEs (typical: Syft
// fills every component with a placeholder vendor=name CPE that
// almost never matches NVD), the enricher MUST validate the existing
// CPE AND append the resolver's authoritative CPE alongside.
// Previously the enricher bailed early on existing CPEs, which is
// why production output had 0 added CPEs despite having an
// authoritative bundled mapping.
func TestEnrichPreservesExistingCPEAndAppendsResolverMatch(t *testing.T) {
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
	hasPreset := false
	for _, cpe := range c.CPEs {
		if cpe == preset {
			hasPreset = true
		}
	}
	if !hasPreset {
		t.Errorf("preset CPE was dropped: %v", c.CPEs)
	}
	if len(c.CPEs) < 2 {
		t.Errorf("CPEs = %v, want preset + resolver match", c.CPEs)
	}
	if c.Properties["astinus:cpe:validated"] != "true" {
		t.Errorf("validated stamp = %q", c.Properties["astinus:cpe:validated"])
	}
	if c.Properties["astinus:cpe:source"] == "" {
		t.Errorf("source stamp missing: %v", c.Properties)
	}
}

// TestEnrichBundledCPEAppendedAlongsideSyftPlaceholder — exercises
// the canonical Syft pattern: every component has a placeholder
// `cpe:2.3:a:lodash:lodash:...` from Syft AND a PURL. The enricher
// should APPEND the bundled `cpe:2.3:a:lodash:lodash:...` (which
// for lodash happens to already match the heuristic; pick a package
// where bundled differs from heuristic).
func TestEnrichBundledCPEAppendedAlongsideSyftPlaceholder(t *testing.T) {
	// log4j-core's NVD vendor:product is apache:log4j — different
	// from the heuristic's "log4j-core:log4j-core". Bundled MUST be
	// the one appended.
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
	wantBundled := "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
	hasBundled := false
	for _, cpe := range c.CPEs {
		if cpe == wantBundled {
			hasBundled = true
		}
	}
	if !hasBundled {
		t.Errorf("bundled CPE %q not appended; got %v", wantBundled, c.CPEs)
	}
	if c.Properties["astinus:cpe:source"] != "bundled" {
		t.Errorf("source = %q, want bundled", c.Properties["astinus:cpe:source"])
	}
	if c.Properties["astinus:cpe:confidence"] != "high" {
		t.Errorf("confidence = %q, want high", c.Properties["astinus:cpe:confidence"])
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
// are dropped during validation; a resolver match is still appended
// when a PURL is present.
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
	for _, cpe := range c.CPEs {
		if cpe == bad {
			t.Errorf("bad CPE was kept: %v", c.CPEs)
		}
	}
	hasGood := false
	for _, cpe := range c.CPEs {
		if cpe == good {
			hasGood = true
		}
	}
	if !hasGood {
		t.Errorf("good CPE was dropped: %v", c.CPEs)
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
