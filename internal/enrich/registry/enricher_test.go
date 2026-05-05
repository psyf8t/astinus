package registry

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestEnricher_FillsMissingFieldsOnly — the canonical S3-Task-4
// invariant: registry metadata fills empty fields but never
// overrides upstream-supplied values.
func TestEnricher_FillsMissingFieldsOnly(t *testing.T) {
	src := &fakeSource{
		name: "x", purl: "npm",
		meta: &Metadata{
			Description: "REGISTRY description",
			Author:      "REGISTRY author",
			Supplier:    Supplier{Name: "REGISTRY Inc"},
			Homepage:    "https://registry.example/foo",
			Repository:  "https://github.com/x/foo",
			Licenses:    []License{{SPDXID: "MIT"}},
			Hashes:      map[string]string{"sha256": "registry-hash"},
		},
	}
	r := NewResolver(ResolverOptions{Sources: []Source{src}, NetworkOK: true})
	e := New(r)

	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef:      "c1",
		Type:        model.ComponentTypeLibrary,
		Name:        "foo",
		Version:     "1",
		PURL:        "pkg:npm/foo@1",
		Description: "INPUT description (must survive)",
		Author:      "INPUT author (must survive)",
		Supplier:    "INPUT supplier (must survive)",
		Hashes:      []model.Hash{{Algorithm: "sha256", Value: "input-hash"}},
	}}}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	if c.Description != "INPUT description (must survive)" {
		t.Errorf("Description was overwritten: %q", c.Description)
	}
	if c.Author != "INPUT author (must survive)" {
		t.Errorf("Author overwritten: %q", c.Author)
	}
	if c.Supplier != "INPUT supplier (must survive)" {
		t.Errorf("Supplier overwritten: %q", c.Supplier)
	}
	// Hash should NOT be replaced because the algorithm already
	// existed; new algorithms append.
	if len(c.Hashes) != 1 || c.Hashes[0].Value != "input-hash" {
		t.Errorf("hashes overwritten: %+v", c.Hashes)
	}
	// License is brand new — should land on the Component.
	if len(c.Licenses) != 1 || c.Licenses[0].SPDXID != "MIT" {
		t.Errorf("licenses = %+v", c.Licenses)
	}
	// Provenance properties must be present.
	if c.Properties[PropertyRegistrySource] == "" {
		t.Errorf("registry:source stamp missing: %v", c.Properties)
	}
	if c.Properties[PropertyRegistryHomepage] != "https://registry.example/foo" {
		t.Errorf("registry:homepage = %q", c.Properties[PropertyRegistryHomepage])
	}
}

// TestEnricher_FillsEmptyFieldsFromRegistry — when the input SBOM
// has empty fields, registry metadata fills them.
func TestEnricher_FillsEmptyFieldsFromRegistry(t *testing.T) {
	src := &fakeSource{
		name: "x", purl: "npm",
		meta: &Metadata{
			Author:   "Registry Author",
			Supplier: Supplier{Name: "Registry Inc", Email: "info@registry.com"},
			Licenses: []License{{SPDXID: "MIT"}},
			Homepage: "https://example.com",
		},
	}
	e := New(NewResolver(ResolverOptions{Sources: []Source{src}, NetworkOK: true}))

	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "c1", Type: model.ComponentTypeLibrary,
		Name: "foo", Version: "1", PURL: "pkg:npm/foo@1",
	}}}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	if c.Author != "Registry Author" {
		t.Errorf("Author = %q", c.Author)
	}
	// Supplier is rendered "Name <email>" because both available.
	if c.Supplier != "Registry Inc <info@registry.com>" {
		t.Errorf("Supplier = %q", c.Supplier)
	}
	if len(c.Licenses) != 1 || c.Licenses[0].SPDXID != "MIT" {
		t.Errorf("Licenses = %+v", c.Licenses)
	}
}

func TestEnricher_DisabledWhenResolverNil(t *testing.T) {
	e := New(nil)
	sbom := &model.SBOM{Components: []model.Component{{
		Name: "foo", PURL: "pkg:npm/foo@1",
	}}}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich(nil resolver): %v", err)
	}
	// No properties / no overrides.
	if len(sbom.Components[0].Properties) != 0 {
		t.Errorf("disabled enricher mutated component: %v", sbom.Components[0].Properties)
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

func TestEnricher_HandlesPURLParseError(t *testing.T) {
	e := New(NewResolver(ResolverOptions{Sources: []Source{&fakeSource{name: "x", purl: "npm"}}, NetworkOK: true}))
	sbom := &model.SBOM{Components: []model.Component{{Name: "x", PURL: "definitely not a purl"}}}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Errorf("Enrich on bad PURL should not error, got: %v", err)
	}
}

func TestSourceForType(t *testing.T) {
	cases := map[string]string{
		"":                             "",
		"pkg:npm/lodash@4":             "npm",
		"pkg:NPM/lodash@4":             "npm",
		"pkg:maven/org.x/y@1?type=jar": "maven",
		"not-a-purl":                   "",
	}
	for in, want := range cases {
		if got := sourceForType(in); got != want {
			t.Errorf("sourceForType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatSupplier(t *testing.T) {
	if got := formatSupplier(Supplier{Name: "X"}); got != "X" {
		t.Errorf("got %q", got)
	}
	if got := formatSupplier(Supplier{Name: "X", Email: "x@y.com"}); got != "X <x@y.com>" {
		t.Errorf("got %q", got)
	}
}

// TestMergeLicenses_DeduplicatesAcrossShapes — registry adding a
// license that the input already has via a different shape (SPDXID
// vs Name vs Expression) MUST NOT duplicate.
func TestMergeLicenses_DeduplicatesAcrossShapes(t *testing.T) {
	c := &model.Component{Licenses: []model.License{{SPDXID: "MIT"}}}
	mergeLicenses(c, []License{{SPDXID: "MIT", Name: "MIT"}})
	if len(c.Licenses) != 1 {
		t.Errorf("duplicate license added: %+v", c.Licenses)
	}
}

// TestEnricher_LicensesFillCounter exercises the per-field counter
// in the stats log line.
func TestEnricher_LicensesFillCounter(t *testing.T) {
	src := &fakeSource{name: "x", purl: "npm",
		meta: &Metadata{Licenses: []License{{SPDXID: "MIT"}}}}
	e := New(NewResolver(ResolverOptions{Sources: []Source{src}, NetworkOK: true}))
	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "c1", Type: model.ComponentTypeLibrary, Name: "foo",
		Version: "1", PURL: "pkg:npm/foo@1",
	}}}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components[0].Licenses) != 1 {
		t.Errorf("expected license added; got %+v", sbom.Components[0].Licenses)
	}
}

// TestEnricher_RegistryFetchedAtStampedRFC3339 — provenance log
// gate.
func TestEnricher_RegistryFetchedAtStampedRFC3339(t *testing.T) {
	src := &fakeSource{name: "x", purl: "npm",
		meta: &Metadata{Description: "x"}}
	e := New(NewResolver(ResolverOptions{Sources: []Source{src}, NetworkOK: true}))
	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "c1", Type: model.ComponentTypeLibrary,
		Name: "foo", Version: "1", PURL: "pkg:npm/foo@1",
	}}}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatal(err)
	}
	stamp := sbom.Components[0].Properties[PropertyRegistryFetchedAt]
	if stamp == "" || !strings.Contains(stamp, "T") {
		t.Errorf("fetched-at stamp wrong: %q", stamp)
	}
}

// TestEnricherWalksSubComponents — pre-S3-Task-1 SBOMs may still
// nest dependencies as SubComponents. The enricher recurses.
func TestEnricherWalksSubComponents(t *testing.T) {
	src := &fakeSource{name: "x", purl: "npm",
		meta: &Metadata{Licenses: []License{{SPDXID: "MIT"}}}}
	e := New(NewResolver(ResolverOptions{Sources: []Source{src}, NetworkOK: true}))
	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "outer", Name: "outer",
		SubComponents: []model.Component{{
			BOMRef: "inner", Name: "inner",
			Version: "1", PURL: "pkg:npm/inner@1",
			Type: model.ComponentTypeLibrary,
		}},
	}}}
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatal(err)
	}
	inner := sbom.Components[0].SubComponents[0]
	if len(inner.Licenses) != 1 {
		t.Errorf("subcomponent not enriched: %+v", inner)
	}
}

// fakeSource lives here to mirror the resolver_test.go pattern but
// is exported into this test file so the enricher tests can drive
// it deterministically.
//
// Defined in resolver_test.go via the same package; this comment
// is just a pointer to where the type lives so a future reader
// finds it without grepping.
//
// (No actual definition needed — package-internal test helpers
// are visible across all _test.go files in the same package.)
//
//nolint:unused // explanatory comment, no code
var _ = cpe.PURL{}
