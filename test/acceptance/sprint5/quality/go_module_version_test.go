//go:build acceptance

package quality

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	s3 "github.com/psyf8t/astinus/test/acceptance/sprint3/helpers"
	s4 "github.com/psyf8t/astinus/test/acceptance/sprint4/helpers"
)

// TestS5T3_BuildinfoVersionWinsOverSyftDifferentVersion — S5 Task 3
// regression gate. When a Go module is reported BOTH by Syft (from
// go.mod / go.sum parsing — the intended dependency) AND by Astinus
// via buildinfo (the actually-compiled version), the buildinfo row
// is authoritative. Pre-S5 the dedup pass merged both rows by PURL,
// keeping the Syft @<intended> shape AND the Astinus @<compiled>
// shape side by side, doubling golang FPs. ADR-0050 + the
// `preferBuildinfoForGoModules` helper drop the non-buildinfo row
// when the module path matches but the version differs.
//
// This test drives an input SBOM with both shapes through the
// binary. The buildinfo row is synthesised by stamping the
// `astinus:identified:source = go-buildinfo` property on the input
// (the CDX reader hydrates it into `model.Component.Properties`
// exactly as the extractor enricher would have produced it). The
// dedup pass MUST observe the marker, treat the row as
// authoritative, and drop the Syft @<intended> sibling.
func TestS5T3_BuildinfoVersionWinsOverSyftDifferentVersion(t *testing.T) {
	const modulePath = "github.com/example/widget"
	const compiledVersion = "v1.5.0"
	const intendedVersion = "v1.2.3"

	identifiedSourceProp := cdx.Property{
		Name:  "astinus:identified:source",
		Value: "go-buildinfo",
	}

	inputSBOM := s4.WriteCDXSBOM(t,
		[]cdx.Component{
			{
				BOMRef:     "comp-buildinfo",
				Type:       cdx.ComponentTypeLibrary,
				Name:       modulePath,
				Version:    compiledVersion,
				PackageURL: "pkg:golang/" + modulePath + "@" + compiledVersion,
				Properties: &[]cdx.Property{identifiedSourceProp},
			},
			{
				// Syft-style row — no astinus:identified:source.
				BOMRef:     "comp-syft",
				Type:       cdx.ComponentTypeLibrary,
				Name:       modulePath,
				Version:    intendedVersion,
				PackageURL: "pkg:golang/" + modulePath + "@" + intendedVersion,
			},
		},
		cdx.Tool{Name: "syft"},
	)

	res := s3.RunEnrichOK(t, s3.EnrichOpts{
		SBOM:      inputSBOM,
		Image:     "test/empty:1",
		NoNetwork: true,
	})
	if res.BOM == nil || res.BOM.Components == nil {
		t.Fatal("no components in output")
	}

	var compiledRow, intendedRow *cdx.Component
	for i := range *res.BOM.Components {
		c := &(*res.BOM.Components)[i]
		switch c.PackageURL {
		case "pkg:golang/" + modulePath + "@" + compiledVersion:
			compiledRow = c
		case "pkg:golang/" + modulePath + "@" + intendedVersion:
			intendedRow = c
		}
	}
	if compiledRow == nil {
		t.Errorf("buildinfo row at %s@%s dropped — preferBuildinfoForGoModules misfired",
			modulePath, compiledVersion)
	}
	if intendedRow != nil {
		t.Errorf("syft-different-version row at %s@%s survived — dedup did not prefer buildinfo (S5-T3 regression)",
			modulePath, intendedVersion)
	}
}

// TestS5T3_BuildinfoSameVersionKeepsSyftBreadcrumb — guards the
// S4-T1 contract clause of ADR-0050: when buildinfo and Syft AGREE
// on the version (same canonical PURL), the rows must merge — the
// Syft row's `syft:location:*` breadcrumb survives while the
// buildinfo provenance wins the primary slot. Dropping the Syft
// row in this case would lose forensic detail downstream consumers
// rely on (path-on-disk for the dependency).
func TestS5T3_BuildinfoSameVersionKeepsSyftBreadcrumb(t *testing.T) {
	const modulePath = "github.com/example/agreed"
	const version = "v0.7.1"

	identifiedSourceProp := cdx.Property{
		Name:  "astinus:identified:source",
		Value: "go-buildinfo",
	}
	syftLocationProp := cdx.Property{
		Name:  "syft:location:0:path",
		Value: "/usr/local/bin/agreed",
	}

	inputSBOM := s4.WriteCDXSBOM(t,
		[]cdx.Component{
			{
				BOMRef:     "comp-buildinfo",
				Type:       cdx.ComponentTypeLibrary,
				Name:       modulePath,
				Version:    version,
				PackageURL: "pkg:golang/" + modulePath + "@" + version,
				Properties: &[]cdx.Property{identifiedSourceProp},
			},
			{
				BOMRef:     "comp-syft",
				Type:       cdx.ComponentTypeLibrary,
				Name:       modulePath,
				Version:    version,
				PackageURL: "pkg:golang/" + modulePath + "@" + version,
				Properties: &[]cdx.Property{syftLocationProp},
			},
		},
		cdx.Tool{Name: "syft"},
	)

	res := s3.RunEnrichOK(t, s3.EnrichOpts{
		SBOM:      inputSBOM,
		Image:     "test/empty:1",
		NoNetwork: true,
	})
	if res.BOM == nil || res.BOM.Components == nil {
		t.Fatal("no components in output")
	}

	merged := s4.FindComponent(res.BOM, modulePath, "pkg:golang/"+modulePath+"@"+version)
	if merged == nil {
		t.Fatalf("same-version merge: row at %s@%s missing from output", modulePath, version)
	}
	if got := s4.PropertyValue(merged, "astinus:identified:source"); got != "go-buildinfo" {
		t.Errorf("astinus:identified:source = %q after merge, want go-buildinfo (buildinfo did not win primary)",
			got)
	}
	if got := s4.PropertyValue(merged, "syft:location:0:path"); got != "/usr/local/bin/agreed" {
		t.Errorf("syft:location:0:path = %q after merge, want preserved Syft breadcrumb (S4-T1 contract regression)",
			got)
	}
}
