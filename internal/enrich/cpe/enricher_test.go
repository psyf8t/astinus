package cpe

import (
	"context"
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

func TestEnrichSkipsComponentsWithCPE(t *testing.T) {
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
	if len(c.CPEs) != 1 || c.CPEs[0] != preset {
		t.Errorf("CPEs changed: %v", c.CPEs)
	}
	if c.Properties["astinus:cpe:validated"] != "true" {
		t.Errorf("validated stamp = %q", c.Properties["astinus:cpe:validated"])
	}
}

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
	if len(c.CPEs) != 1 || c.CPEs[0] != good {
		t.Errorf("CPEs = %v, want only %q", c.CPEs, good)
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
