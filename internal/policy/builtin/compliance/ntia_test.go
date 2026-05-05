package compliance

import (
	"context"
	"testing"
	"time"

	"github.com/psyf8t/astinus/internal/policy"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// fully-compliant SBOM: 1 component with all NTIA elements + 1
// relationship + Author + Timestamp.
func compliantSBOM() *model.SBOM {
	return &model.SBOM{
		Metadata: model.Metadata{
			Timestamp: time.Now(),
			Authors:   []string{"ops@example.com"},
		},
		Components: []model.Component{{
			BOMRef:   "comp-1",
			Type:     model.ComponentTypeLibrary,
			Name:     "lodash",
			Version:  "4.17.21",
			Supplier: "lodash maintainers",
			PURL:     "pkg:npm/lodash@4.17.21",
		}},
	}
}

func TestNTIACompliantSBOMHasNoFindings(t *testing.T) {
	v := NewNTIA()
	out, err := v.Validate(context.Background(), compliantSBOM())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("compliant SBOM produced %d findings: %+v", len(out), out)
	}
}

func TestNTIAMissingVersion(t *testing.T) {
	sbom := compliantSBOM()
	sbom.Components[0].Version = ""
	out, _ := NewNTIA().Validate(context.Background(), sbom)
	if !hasFindingByID(out, "NTIA-VERSION") {
		t.Errorf("expected NTIA-VERSION finding, got %+v", out)
	}
}

func TestNTIAMissingName(t *testing.T) {
	sbom := compliantSBOM()
	sbom.Components[0].Name = ""
	out, _ := NewNTIA().Validate(context.Background(), sbom)
	got := findingByID(out, "NTIA-NAME")
	if got == nil {
		t.Fatal("expected NTIA-NAME finding")
	}
	if got.Severity != policy.SeverityCritical {
		t.Errorf("Severity = %s, want critical", got.Severity)
	}
}

func TestNTIAMissingSupplierAndAuthor(t *testing.T) {
	sbom := compliantSBOM()
	sbom.Components[0].Supplier = ""
	sbom.Components[0].Author = ""
	out, _ := NewNTIA().Validate(context.Background(), sbom)
	if !hasFindingByID(out, "NTIA-SUPPLIER") {
		t.Errorf("expected NTIA-SUPPLIER finding")
	}
}

func TestNTIASupplierAuthorEitherSatisfies(t *testing.T) {
	sbom := compliantSBOM()
	sbom.Components[0].Supplier = ""
	sbom.Components[0].Author = "Some Author"
	out, _ := NewNTIA().Validate(context.Background(), sbom)
	if hasFindingByID(out, "NTIA-SUPPLIER") {
		t.Errorf("Author should satisfy supplier element")
	}
}

func TestNTIANoIdentifier(t *testing.T) {
	sbom := compliantSBOM()
	sbom.Components[0].PURL = ""
	sbom.Components[0].CPEs = nil
	out, _ := NewNTIA().Validate(context.Background(), sbom)
	if !hasFindingByID(out, "NTIA-IDENTIFIER") {
		t.Errorf("expected NTIA-IDENTIFIER finding")
	}
}

func TestNTIACPESatisfiesIdentifier(t *testing.T) {
	sbom := compliantSBOM()
	sbom.Components[0].PURL = ""
	sbom.Components[0].CPEs = []string{"cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*"}
	out, _ := NewNTIA().Validate(context.Background(), sbom)
	if hasFindingByID(out, "NTIA-IDENTIFIER") {
		t.Errorf("CPE should satisfy identifier element")
	}
}

func TestNTIASkipsTypeFile(t *testing.T) {
	sbom := compliantSBOM()
	sbom.Components = append(sbom.Components, model.Component{
		BOMRef: "f1",
		Type:   model.ComponentTypeFile,
		Name:   "", // would normally trigger NTIA-NAME
	})
	out, _ := NewNTIA().Validate(context.Background(), sbom)
	if hasFindingByID(out, "NTIA-NAME") {
		t.Errorf("type=file Components must be skipped")
	}
}

func TestNTIAMissingMetadataAuthor(t *testing.T) {
	sbom := compliantSBOM()
	sbom.Metadata.Authors = nil
	sbom.Metadata.Tools = nil
	out, _ := NewNTIA().Validate(context.Background(), sbom)
	if !hasFindingByID(out, "NTIA-METADATA-AUTHOR") {
		t.Errorf("expected NTIA-METADATA-AUTHOR finding")
	}
}

func TestNTIAToolsCountAsAuthor(t *testing.T) {
	sbom := compliantSBOM()
	sbom.Metadata.Authors = nil
	sbom.Metadata.Tools = []model.Tool{{Name: "syft", Version: "1.0"}}
	out, _ := NewNTIA().Validate(context.Background(), sbom)
	if hasFindingByID(out, "NTIA-METADATA-AUTHOR") {
		t.Errorf("Tools should satisfy Author element")
	}
}

func TestNTIAMissingTimestamp(t *testing.T) {
	sbom := compliantSBOM()
	sbom.Metadata.Timestamp = time.Time{}
	out, _ := NewNTIA().Validate(context.Background(), sbom)
	if !hasFindingByID(out, "NTIA-METADATA-TIMESTAMP") {
		t.Errorf("expected NTIA-METADATA-TIMESTAMP finding")
	}
}

func TestNTIARelationshipsThreshold(t *testing.T) {
	sbom := compliantSBOM()
	// pad to >=10 components, no relationships
	for i := 0; i < 12; i++ {
		sbom.Components = append(sbom.Components, model.Component{
			BOMRef:   "c" + string(rune('a'+i)),
			Type:     model.ComponentTypeLibrary,
			Name:     "lib" + string(rune('a'+i)),
			Version:  "1.0",
			PURL:     "pkg:npm/lib" + string(rune('a'+i)),
			Supplier: "x",
		})
	}
	out, _ := NewNTIA().Validate(context.Background(), sbom)
	if !hasFindingByID(out, "NTIA-RELATIONSHIPS") {
		t.Errorf("expected NTIA-RELATIONSHIPS finding for %d-component SBOM with no relationships",
			len(sbom.Components))
	}
}

func TestNTIASmallSBOMNoRelationshipsOK(t *testing.T) {
	sbom := compliantSBOM() // 1 component
	out, _ := NewNTIA().Validate(context.Background(), sbom)
	if hasFindingByID(out, "NTIA-RELATIONSHIPS") {
		t.Errorf("1-component SBOM should not trigger NTIA-RELATIONSHIPS")
	}
}

func TestNTIANilSBOM(t *testing.T) {
	out, err := NewNTIA().Validate(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Errorf("nil SBOM should return nil findings, got %+v", out)
	}
}

// ─── Helpers ────────────────────────────────────────────────────────

func hasFindingByID(findings []policy.Finding, id string) bool {
	return findingByID(findings, id) != nil
}

func findingByID(findings []policy.Finding, id string) *policy.Finding {
	for i := range findings {
		if findings[i].RuleID == id {
			return &findings[i]
		}
	}
	return nil
}
