package lifecycle

import (
	"context"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestEnricher_StampsLifecyclePropertiesOnNode — canonical happy
// path: Node 20 component flows through the enricher with the
// bundled snapshot serving the data.
func TestEnricher_StampsLifecyclePropertiesOnNode(t *testing.T) {
	bundled, err := LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	r := NewResolver(ResolverOptions{Bundled: bundled, Mode: ModeOffline})
	// Pick a clock between Node 20's active-support end (2024-10-22)
	// and EOL (2026-04-30) — the maintenance window.
	e := New(r).WithClock(func() time.Time {
		return time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC)
	})
	sbom := &model.SBOM{Components: []model.Component{{
		Name: "node", Version: "20.18.0", Type: model.ComponentTypeApplication,
	}}}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	for _, want := range []struct {
		key, expected string
	}{
		{PropertyLifecycleProduct, "nodejs"},
		{PropertyLifecycleCycle, "20"},
		{PropertyLifecycleEOL, "2026-04-30"},
		{PropertyLifecycleLTS, "true"},
		{PropertyLifecycleStatus, string(StatusMaintenance)},
		{PropertyLifecycleSource, "bundled"},
	} {
		if c.Properties[want.key] == "" {
			t.Errorf("%s missing", want.key)
			continue
		}
		if c.Properties[want.key] != want.expected {
			t.Errorf("%s = %q, want %q", want.key, c.Properties[want.key], want.expected)
		}
	}
}

// TestEnricher_DaysUntilEOLNegativeForPastEOL — Components with
// already-past EOL get a negative days count.
func TestEnricher_DaysUntilEOLNegativeForPastEOL(t *testing.T) {
	bundled, err := LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	e := New(NewResolver(ResolverOptions{Bundled: bundled, Mode: ModeOffline})).
		WithClock(func() time.Time {
			return time.Date(2026, 5, 4, 0, 0, 0, 0, time.UTC)
		})
	sbom := &model.SBOM{Components: []model.Component{{
		Name: "node", Version: "16.20.2", Type: model.ComponentTypeApplication,
	}}}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	if c.Properties[PropertyLifecycleStatus] != string(StatusEOL) {
		t.Errorf("status = %q, want eol", c.Properties[PropertyLifecycleStatus])
	}
	days, err := strconv.Atoi(c.Properties[PropertyLifecycleDaysUntilEOL])
	if err != nil {
		t.Fatalf("days = %q (parse: %v)", c.Properties[PropertyLifecycleDaysUntilEOL], err)
	}
	if days >= 0 {
		t.Errorf("days = %d, want negative for past-EOL Node 16", days)
	}
}

// TestEnricher_LeavesNonMappedComponentsUntouched — npm libraries
// don't map to any endoflife product; the enricher MUST not stamp
// anything on them.
func TestEnricher_LeavesNonMappedComponentsUntouched(t *testing.T) {
	bundled, err := LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	e := New(NewResolver(ResolverOptions{Bundled: bundled, Mode: ModeOffline}))
	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "lib1", Type: model.ComponentTypeLibrary,
		Name: "lodash", Version: "4.17.21",
		PURL: "pkg:npm/lodash@4.17.21",
	}}}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	for k := range sbom.Components[0].Properties {
		if hasPrefix(k, "astinus:lifecycle:") {
			t.Errorf("unmapped component carries lifecycle stamp: %q", k)
		}
	}
}

// TestEnricher_DisabledWhenResolverNil — `--no-lifecycle` path.
func TestEnricher_DisabledWhenResolverNil(t *testing.T) {
	e := New(nil)
	sbom := &model.SBOM{Components: []model.Component{{
		Name: "node", Version: "20.18.0",
	}}}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich(nil resolver): %v", err)
	}
	for k := range sbom.Components[0].Properties {
		if hasPrefix(k, "astinus:lifecycle:") {
			t.Errorf("disabled enricher mutated component: %q", k)
		}
	}
}

func TestEnricher_NilSBOM(t *testing.T) {
	e := New(NewResolver(ResolverOptions{}))
	if err := e.Enrich(context.Background(), nil, nil); err == nil {
		t.Fatal("expected error on nil SBOM")
	}
}

func TestEnricher_DependenciesContract(t *testing.T) {
	deps := (&Enricher{}).Dependencies()
	if !slices.Contains(deps, "untracked") || !slices.Contains(deps, "extractor") {
		t.Errorf("Dependencies = %v, want both untracked + extractor", deps)
	}
}

// TestEnricher_FreshComponentIsActive — a component whose EOL is
// well in the future surfaces as active.
func TestEnricher_FreshComponentIsActive(t *testing.T) {
	bundled, err := LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	e := New(NewResolver(ResolverOptions{Bundled: bundled, Mode: ModeOffline})).
		WithClock(func() time.Time {
			return time.Date(2024, 10, 1, 0, 0, 0, 0, time.UTC)
		})
	sbom := &model.SBOM{Components: []model.Component{{
		Name: "node", Version: "22.10.0", Type: model.ComponentTypeApplication,
	}}}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got := sbom.Components[0].Properties[PropertyLifecycleStatus]; got != string(StatusActive) {
		t.Errorf("status = %q, want active", got)
	}
}

// TestEnricher_RecursesIntoSubComponents — pre-S3-Task-1 SBOMs
// may nest dependencies.
func TestEnricher_RecursesIntoSubComponents(t *testing.T) {
	bundled, err := LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	e := New(NewResolver(ResolverOptions{Bundled: bundled, Mode: ModeOffline}))
	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "outer", Name: "outer",
		SubComponents: []model.Component{{
			Name: "node", Version: "20.18.0",
			Type: model.ComponentTypeApplication,
		}},
	}}}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatal(err)
	}
	inner := sbom.Components[0].SubComponents[0]
	if inner.Properties[PropertyLifecycleProduct] != "nodejs" {
		t.Errorf("subcomponent not enriched: %v", inner.Properties)
	}
}

func TestFormatDate(t *testing.T) {
	if formatDate(time.Time{}) != "" {
		t.Error("zero time should format as empty")
	}
	if got := formatDate(time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC)); got != "2026-04-30" {
		t.Errorf("got %q", got)
	}
}

// hasPrefix is a tiny inlined helper to avoid pulling strings into
// the test file's import list (used only here).
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
