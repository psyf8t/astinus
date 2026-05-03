package compliance

import (
	"context"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestEUCRAVulnHandlingSatisfiedByNVDSource(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef:  "c1",
			Type:    model.ComponentTypeLibrary,
			Name:    "lodash",
			Version: "1.0",
			PURL:    "pkg:npm/lodash@1.0",
			Properties: map[string]string{
				"astinus:cpe:source": "nvd-api",
			},
		}},
	}
	out, _ := NewEUCRA().Validate(context.Background(), sbom)
	if hasFindingByID(out, "EU-CRA-ART13-VULN-HANDLING") {
		t.Errorf("nvd-api source should satisfy vuln-handling")
	}
}

func TestEUCRAVulnHandlingSatisfiedByDisclosureProperty(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef:  "c1",
			Type:    model.ComponentTypeLibrary,
			Name:    "lodash",
			Version: "1.0",
			Properties: map[string]string{
				"astinus:references:vuln-disclosure": "https://example.com/security",
			},
		}},
	}
	out, _ := NewEUCRA().Validate(context.Background(), sbom)
	if hasFindingByID(out, "EU-CRA-ART13-VULN-HANDLING") {
		t.Errorf("disclosure URL should satisfy vuln-handling")
	}
}

func TestEUCRAVulnHandlingMissing(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef:  "c1",
			Type:    model.ComponentTypeLibrary,
			Name:    "lodash",
			Version: "1.0",
			// no astinus:cpe:source, no disclosure URL
		}},
	}
	out, _ := NewEUCRA().Validate(context.Background(), sbom)
	if !hasFindingByID(out, "EU-CRA-ART13-VULN-HANDLING") {
		t.Errorf("expected vuln-handling finding when no signal present")
	}
}

func TestEUCRAMajorFrameworkLicenseMissing(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef:  "c1",
			Type:    model.ComponentTypeFramework,
			Name:    "spring-core",
			Version: "6.0",
			PURL:    "pkg:maven/org.springframework/spring-core@6.0",
			Properties: map[string]string{
				"astinus:cpe:source": "nvd-api", // satisfies vuln-handling
			},
			// no Licenses
		}},
	}
	out, _ := NewEUCRA().Validate(context.Background(), sbom)
	if !hasFindingByID(out, "EU-CRA-ART13-LICENSE") {
		t.Errorf("expected license finding for major framework w/o license")
	}
}

func TestEUCRAUtilityLibraryLicenseSkipped(t *testing.T) {
	// pkg:npm/lodash with type=library is NOT a major framework;
	// no license finding expected even when Licenses is empty.
	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef:  "c1",
			Type:    model.ComponentTypeLibrary,
			Name:    "lodash",
			Version: "1.0",
			PURL:    "pkg:npm/lodash@1.0",
			Properties: map[string]string{
				"astinus:cpe:source": "nvd-api",
			},
		}},
	}
	out, _ := NewEUCRA().Validate(context.Background(), sbom)
	if hasFindingByID(out, "EU-CRA-ART13-LICENSE") {
		t.Errorf("library type should not trigger major-framework license check")
	}
}

func TestEUCRASkipsTypeFile(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef: "f1",
			Type:   model.ComponentTypeFile,
			Name:   "etc-file",
			Properties: map[string]string{
				"astinus:cpe:source": "nvd-api",
			},
		}},
	}
	out, _ := NewEUCRA().Validate(context.Background(), sbom)
	for _, f := range out {
		if f.Component == "f1" {
			t.Errorf("type=file should be skipped, got finding %+v", f)
		}
	}
}

func TestEUCRANilSBOM(t *testing.T) {
	out, err := NewEUCRA().Validate(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Errorf("got %+v, want nil", out)
	}
}
