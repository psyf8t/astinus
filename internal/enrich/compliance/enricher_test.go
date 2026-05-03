package compliance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/psyf8t/astinus/internal/policy"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// stubValidator returns a configured findings slice on every call.
type stubValidator struct {
	name     string
	findings []policy.Finding
	err      error
}

func (s *stubValidator) Name() string        { return s.name }
func (s *stubValidator) Description() string { return "stub for tests" }
func (s *stubValidator) Validate(_ context.Context, _ *model.SBOM) ([]policy.Finding, error) {
	return s.findings, s.err
}

func TestEnricherEnrichRequiresNonNilSBOM(t *testing.T) {
	if err := New().Enrich(context.Background(), nil, nil); err == nil {
		t.Fatal("expected error for nil sbom")
	}
}

func TestEnricherStampsAggregateCounts(t *testing.T) {
	e := NewWithValidators(&stubValidator{
		name: "test",
		findings: []policy.Finding{
			{Severity: policy.SeverityCritical, RuleID: "X1"},
			{Severity: policy.SeverityHigh, RuleID: "X2"},
			{Severity: policy.SeverityHigh, RuleID: "X3"},
			{Severity: policy.SeverityMedium, RuleID: "X4"},
			{Severity: policy.SeverityLow, RuleID: "X5"},
		},
	})
	sbom := &model.SBOM{}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		model.PropertyComplianceFindingsCount: "5",
		model.PropertyComplianceCriticalCount: "1",
		model.PropertyComplianceHighCount:     "2",
		model.PropertyComplianceMediumCount:   "1",
		model.PropertyComplianceLowCount:      "1",
	}
	for k, want := range cases {
		if got := sbom.Metadata.Properties[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestEnricherStampsPerValidatorStatus(t *testing.T) {
	e := NewWithValidators(
		&stubValidator{name: "v1", findings: nil}, // passed
		&stubValidator{name: "v2", findings: []policy.Finding{
			{Severity: policy.SeverityLow, RuleID: "L1"},
		}}, // passed-with-warnings
		&stubValidator{name: "v3", findings: []policy.Finding{
			{Severity: policy.SeverityHigh, RuleID: "H1"},
		}}, // failed
	)
	sbom := &model.SBOM{}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"astinus:compliance:v1:status": "passed",
		"astinus:compliance:v2:status": "passed-with-warnings",
		"astinus:compliance:v3:status": "failed",
	}
	for k, want := range cases {
		if got := sbom.Metadata.Properties[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestEnricherStampsPerComponentFinding(t *testing.T) {
	e := NewWithValidators(&stubValidator{
		name: "test",
		findings: []policy.Finding{
			{Severity: policy.SeverityHigh, RuleID: "NTIA-VERSION", Component: "comp-1"},
		},
	})
	sbom := &model.SBOM{
		Components: []model.Component{{BOMRef: "comp-1", Name: "x"}},
	}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatal(err)
	}
	got := sbom.Components[0].Properties["astinus:compliance:finding:NTIA-VERSION"]
	if got != "high" {
		t.Errorf("per-component finding stamp = %q, want high", got)
	}
}

func TestEnricherSkipsFindingForUnknownComponent(t *testing.T) {
	e := NewWithValidators(&stubValidator{
		name: "test",
		findings: []policy.Finding{
			{Severity: policy.SeverityHigh, RuleID: "X", Component: "ghost"},
		},
	})
	sbom := &model.SBOM{
		Components: []model.Component{{BOMRef: "real", Name: "x"}},
	}
	// Should not panic; the unknown BOMRef just doesn't get a stamp.
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range sbom.Components {
		for k := range c.Properties {
			if strings.HasPrefix(k, "astinus:compliance:finding:") {
				t.Errorf("unexpected per-component stamp: %s", k)
			}
		}
	}
}

func TestEnricherValidatorErrorDoesNotAbortChain(t *testing.T) {
	working := &stubValidator{
		name: "ok",
		findings: []policy.Finding{
			{Severity: policy.SeverityLow, RuleID: "L1"},
		},
	}
	broken := &stubValidator{name: "broken", err: context.DeadlineExceeded}
	e := NewWithValidators(broken, working)
	sbom := &model.SBOM{}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatal(err)
	}
	// "ok" validator's findings should still land.
	if sbom.Metadata.Properties[model.PropertyComplianceFindingsCount] != "1" {
		t.Errorf("findings-count = %q, want 1",
			sbom.Metadata.Properties[model.PropertyComplianceFindingsCount])
	}
	if got := sbom.Metadata.Properties["astinus:compliance:broken:status"]; got != "errored" {
		t.Errorf("broken status = %q, want errored", got)
	}
}

func TestEnricherFindingsHelperReplaysValidators(t *testing.T) {
	e := NewWithValidators(&stubValidator{
		name: "test",
		findings: []policy.Finding{
			{Severity: policy.SeverityCritical, RuleID: "X"},
		},
	})
	got := e.Findings(context.Background(), &model.SBOM{})
	if len(got) != 1 || got[0].RuleID != "X" {
		t.Errorf("Findings() = %+v, want one X", got)
	}
}

func TestEnricherDependenciesIsDedup(t *testing.T) {
	e := New()
	deps := e.Dependencies()
	if len(deps) != 1 || deps[0] != "dedup" {
		t.Errorf("Dependencies = %v, want [dedup]", deps)
	}
}

func TestEnricherRunsBundledDefaults(t *testing.T) {
	// Smoke test: New().Enrich on a roughly compliant SBOM
	// should produce some findings (NTIA + EU CRA + structural
	// won't all pass on a one-liner) and not crash.
	sbom := &model.SBOM{
		Metadata: model.Metadata{
			Timestamp: time.Now(),
			Authors:   []string{"ops"},
		},
		Components: []model.Component{{
			BOMRef:   "c1",
			Type:     model.ComponentTypeLibrary,
			Name:     "lodash",
			Version:  "4.17.21",
			PURL:     "pkg:npm/lodash@4.17.21",
			Supplier: "lodash",
		}},
	}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatal(err)
	}
	if sbom.Metadata.Properties[model.PropertyComplianceFindingsCount] == "" {
		t.Errorf("findings-count not stamped")
	}
}
