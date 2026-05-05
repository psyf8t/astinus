package compliance

import (
	"context"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// ─── CycloneDX structural ────────────────────────────────────────

func TestCDXStructuralEmptyComponents(t *testing.T) {
	out, _ := NewCycloneDXStructural().Validate(context.Background(), &model.SBOM{})
	if !hasFindingByID(out, "CDX-EMPTY-COMPONENTS") {
		t.Errorf("expected CDX-EMPTY-COMPONENTS finding")
	}
}

func TestCDXStructuralNameMissing(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "c1", Type: model.ComponentTypeLibrary,
	}}}
	out, _ := NewCycloneDXStructural().Validate(context.Background(), sbom)
	if !hasFindingByID(out, "CDX-COMPONENT-NAME-MISSING") {
		t.Errorf("expected CDX-COMPONENT-NAME-MISSING finding")
	}
}

func TestCDXStructuralInvalidType(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "c1", Name: "x", Type: "made-up-type",
	}}}
	out, _ := NewCycloneDXStructural().Validate(context.Background(), sbom)
	if !hasFindingByID(out, "CDX-COMPONENT-TYPE-INVALID") {
		t.Errorf("expected CDX-COMPONENT-TYPE-INVALID finding")
	}
}

func TestCDXStructuralValidComponentsHaveNoFindings(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "c1", Name: "lodash", Type: model.ComponentTypeLibrary,
	}}}
	out, _ := NewCycloneDXStructural().Validate(context.Background(), sbom)
	if len(out) != 0 {
		t.Errorf("valid SBOM produced %d findings: %+v", len(out), out)
	}
}

func TestCDXStructuralBOMRefDuplicate(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{
		{BOMRef: "shared", Name: "a", Type: model.ComponentTypeLibrary},
		{BOMRef: "shared", Name: "b", Type: model.ComponentTypeLibrary},
	}}
	out, _ := NewCycloneDXStructural().Validate(context.Background(), sbom)
	if !hasFindingByID(out, "CDX-BOMREF-DUPLICATE") {
		t.Errorf("expected CDX-BOMREF-DUPLICATE finding")
	}
}

func TestCDXStructuralEmptyBOMRefDoesNotTriggerDup(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{
		{Name: "a", Type: model.ComponentTypeLibrary},
		{Name: "b", Type: model.ComponentTypeLibrary},
	}}
	out, _ := NewCycloneDXStructural().Validate(context.Background(), sbom)
	if hasFindingByID(out, "CDX-BOMREF-DUPLICATE") {
		t.Errorf("empty BOMRef should not trigger dup-check")
	}
}

func TestCDXStructuralRecursesIntoSubComponents(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "outer", Name: "outer", Type: model.ComponentTypeApplication,
		SubComponents: []model.Component{{
			BOMRef: "inner", Name: "", Type: model.ComponentTypeLibrary,
		}},
	}}}
	out, _ := NewCycloneDXStructural().Validate(context.Background(), sbom)
	if !hasFindingByID(out, "CDX-COMPONENT-NAME-MISSING") {
		t.Errorf("expected name-missing finding for sub-component")
	}
}

// ─── SPDX structural ─────────────────────────────────────────────

func TestSPDXStructuralEmptyPackages(t *testing.T) {
	out, _ := NewSPDXStructural().Validate(context.Background(), &model.SBOM{})
	if !hasFindingByID(out, "SPDX-EMPTY-PACKAGES") {
		t.Errorf("expected SPDX-EMPTY-PACKAGES finding")
	}
}

func TestSPDXStructuralPackageNameMissing(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{BOMRef: "c1"}}}
	out, _ := NewSPDXStructural().Validate(context.Background(), sbom)
	if !hasFindingByID(out, "SPDX-PACKAGE-NAME-MISSING") {
		t.Errorf("expected SPDX-PACKAGE-NAME-MISSING finding")
	}
}

func TestSPDXStructuralDownloadLocationDefault(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "c1", Name: "lodash",
	}}}
	out, _ := NewSPDXStructural().Validate(context.Background(), sbom)
	if !hasFindingByID(out, "SPDX-DOWNLOAD-LOCATION-NOASSERTION") {
		t.Errorf("expected SPDX-DOWNLOAD-LOCATION-NOASSERTION finding")
	}
}

func TestSPDXStructuralLicenseDefault(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "c1", Name: "lodash", PURL: "pkg:npm/lodash",
	}}}
	out, _ := NewSPDXStructural().Validate(context.Background(), sbom)
	if !hasFindingByID(out, "SPDX-LICENSE-NOASSERTION") {
		t.Errorf("expected SPDX-LICENSE-NOASSERTION finding")
	}
}

func TestSPDXStructuralCleanComponentHasOnlyLicenseFinding(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "c1",
		Name:   "lodash",
		PURL:   "pkg:npm/lodash@4.17.21",
		Licenses: []model.License{{
			Expression: "MIT",
		}},
	}}}
	out, _ := NewSPDXStructural().Validate(context.Background(), sbom)
	if len(out) != 0 {
		t.Errorf("clean SPDX-shape SBOM produced %d findings: %+v", len(out), out)
	}
}
