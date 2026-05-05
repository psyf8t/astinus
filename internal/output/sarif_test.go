package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestSARIFRendererProducesValidJSON(t *testing.T) {
	r, err := Get(FormatSARIF, Options{Pretty: true})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if r.Name() != FormatSARIF {
		t.Errorf("Name = %q", r.Name())
	}
	if r.MIMEType() != "application/sarif+json" {
		t.Errorf("MIMEType = %q", r.MIMEType())
	}

	var buf bytes.Buffer
	if err := r.Render(&buf, sampleSBOM()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, buf.String())
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v", doc["version"])
	}
	if _, ok := doc["$schema"]; !ok {
		t.Error("$schema missing")
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %v", doc["runs"])
	}
}

func TestSARIFEmitsAllFindingTypes(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{
			// Untracked + missing CPE.
			{
				BOMRef: "untracked-jq", Name: "jq", Version: "1.7.1",
				Evidence: &model.Evidence{
					Method:    "untracked-scan",
					Locations: []model.EvidenceLocation{{Path: "/usr/local/bin/jq"}},
				},
				Properties: map[string]string{"astinus:untracked:category": "executable"},
			},
			// Origin unknown + missing CPE.
			{
				BOMRef: "no-origin", Name: "x", PURL: "pkg:generic/x@1.0", Origin: model.OriginUnknown,
			},
			// Low-confidence CPE.
			{
				BOMRef: "low-conf", Name: "y", PURL: "pkg:gem/y@1.0",
				CPEs:       []string{"cpe:2.3:a:y:y:1.0:*:*:*:*:*:*:*"},
				Properties: map[string]string{"astinus:cpe:confidence": "low"},
			},
			// Clean — should produce no results.
			{
				BOMRef: "clean", Name: "z", Version: "1.0", Origin: model.OriginBaseImage,
				CPEs:       []string{"cpe:2.3:a:z:z:1.0:*:*:*:*:*:*:*"},
				Properties: map[string]string{"astinus:cpe:confidence": "high"},
			},
		},
	}

	r, _ := Get(FormatSARIF, Options{})
	var buf bytes.Buffer
	if err := r.Render(&buf, sbom); err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct{ Text string }
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}

	results := doc.Runs[0].Results
	want := map[string]string{
		ruleUntracked:        "warning",
		ruleOriginUnknown:    "note",
		ruleMissingCPE:       "note",
		ruleLowConfidenceCPE: "note",
	}
	got := map[string]string{}
	for _, r := range results {
		got[r.RuleID] = r.Level
	}
	for id, wantLevel := range want {
		if gotLevel, ok := got[id]; !ok {
			t.Errorf("missing %s result", id)
		} else if gotLevel != wantLevel {
			t.Errorf("%s level = %q, want %q", id, gotLevel, wantLevel)
		}
	}
}

func TestSARIFCleanSBOMHasZeroResults(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef: "clean", Name: "x", Version: "1.0",
			Origin: model.OriginBaseImage,
			CPEs:   []string{"cpe:2.3:a:x:x:1.0:*:*:*:*:*:*:*"},
		}},
	}
	r, _ := Get(FormatSARIF, Options{})
	var buf bytes.Buffer
	_ = r.Render(&buf, sbom)
	if !strings.Contains(buf.String(), `"results":null`) && !strings.Contains(buf.String(), `"results":[]`) {
		// json.Marshal of a nil slice writes "null"; a zero-length
		// non-nil slice writes "[]". Either is acceptable.
		t.Errorf("expected empty results array, got:\n%s", buf.String())
	}
}

func TestSARIFRendererNilSBOM(t *testing.T) {
	r, _ := Get(FormatSARIF, Options{})
	if err := r.Render(&bytes.Buffer{}, nil); err == nil {
		t.Fatal("expected error for nil sbom")
	}
}

func TestSARIFCleanURIStripsLeadingSlash(t *testing.T) {
	if got := cleanURI("/usr/bin/jq"); got != "usr/bin/jq" {
		t.Errorf("got %q", got)
	}
	if got := cleanURI("usr/bin/jq"); got != "usr/bin/jq" {
		t.Errorf("got %q", got)
	}
}

func TestSARIFRecursesIntoSubComponents(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef: "outer", Name: "outer",
			SubComponents: []model.Component{{
				BOMRef: "inner", Name: "inner", Origin: model.OriginUnknown,
			}},
		}},
	}
	r, _ := Get(FormatSARIF, Options{})
	var buf bytes.Buffer
	_ = r.Render(&buf, sbom)
	if !strings.Contains(buf.String(), `"inner"`) {
		t.Errorf("subcomponent rule not emitted:\n%s", buf.String())
	}
}

// sampleSBOM gives the SARIF + summary tests something plausible to
// render. Hand-built (no fixture file).
func sampleSBOM() *model.SBOM {
	return &model.SBOM{
		Metadata: model.Metadata{
			Component: &model.Component{
				BOMRef:  "myapp",
				Name:    "myapp",
				Version: "1.2.3",
			},
		},
		Components: []model.Component{
			{BOMRef: "a", Name: "a", Origin: model.OriginUnknown},
		},
	}
}
