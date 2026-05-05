package cyclonedx_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/cyclonedx"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// fixtureDir is resolved relative to the package directory so tests run
// regardless of the working directory.
const fixtureDir = "../../../test/fixtures/sboms/cyclonedx"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return body
}

func TestRoundTripJSONFixtures(t *testing.T) {
	fixtures := []string{
		"empty.cdx.json",
		"syft-alpine.cdx.json",
		"syft-nginx.cdx.json",
		"trivy-ubuntu.cdx.json",
		"nested-components.cdx.json",
		"with-evidence.cdx.json",
		"already-enriched.cdx.json",
	}
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			body := loadFixture(t, name)

			sbom, err := cyclonedx.ReadJSON(bytes.NewReader(body))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if sbom.SourceFormat != model.FormatCycloneDXJSON {
				t.Errorf("SourceFormat = %v, want %v", sbom.SourceFormat, model.FormatCycloneDXJSON)
			}
			if !bytes.Equal(sbom.SourceRaw, body) {
				t.Errorf("SourceRaw should equal input")
			}

			var buf bytes.Buffer
			if err := cyclonedx.WriteJSON(&buf, sbom, cyclonedx.WriteOptions{Pretty: true}); err != nil {
				t.Fatalf("write: %v", err)
			}

			// Re-read the output and compare canonical form to canonical form.
			roundTripped, err := cyclonedx.ReadJSON(bytes.NewReader(buf.Bytes()))
			if err != nil {
				t.Fatalf("re-read: %v", err)
			}

			assertSBOMSemanticEqual(t, sbom, roundTripped)
		})
	}
}

// assertSBOMSemanticEqual checks the canonical-model fields that should
// survive a CDX round-trip. SourceRaw / SourceFormat differ by
// definition (different bytes the second time around) so they're
// excluded.
func assertSBOMSemanticEqual(t *testing.T, a, b *model.SBOM) {
	t.Helper()
	// Top-level properties
	if !reflect.DeepEqual(normalizeProps(a.Properties), normalizeProps(b.Properties)) {
		t.Errorf("Properties differ:\n  a=%v\n  b=%v", a.Properties, b.Properties)
	}
	// Metadata
	if !metadataEqual(a.Metadata, b.Metadata) {
		t.Errorf("Metadata differ:\n  a=%+v\n  b=%+v", a.Metadata, b.Metadata)
	}
	// Components — order preserved by writer.
	if len(a.Components) != len(b.Components) {
		t.Fatalf("component count differs: a=%d b=%d", len(a.Components), len(b.Components))
	}
	for i := range a.Components {
		if !componentEqual(a.Components[i], b.Components[i]) {
			t.Errorf("component[%d] differs:\n  a=%+v\n  b=%+v", i, a.Components[i], b.Components[i])
		}
	}
	// Relationships — order preserved per source ref.
	if !relationshipsEqual(a.Relationships, b.Relationships) {
		t.Errorf("Relationships differ:\n  a=%v\n  b=%v", a.Relationships, b.Relationships)
	}
}

func metadataEqual(a, b model.Metadata) bool {
	if !a.Timestamp.Equal(b.Timestamp) {
		return false
	}
	if !reflect.DeepEqual(normalizeStrings(a.Authors), normalizeStrings(b.Authors)) {
		return false
	}
	if !reflect.DeepEqual(a.Tools, b.Tools) {
		return false
	}
	if (a.Component == nil) != (b.Component == nil) {
		return false
	}
	if a.Component != nil && !componentEqual(*a.Component, *b.Component) {
		return false
	}
	return reflect.DeepEqual(normalizeProps(a.Properties), normalizeProps(b.Properties))
}

func componentEqual(a, b model.Component) bool {
	a.Properties = normalizeProps(a.Properties)
	b.Properties = normalizeProps(b.Properties)
	a.CPEs = normalizeStrings(a.CPEs)
	b.CPEs = normalizeStrings(b.CPEs)
	if len(a.SubComponents) != len(b.SubComponents) {
		return false
	}
	for i := range a.SubComponents {
		if !componentEqual(a.SubComponents[i], b.SubComponents[i]) {
			return false
		}
	}
	a.SubComponents, b.SubComponents = nil, nil
	return reflect.DeepEqual(a, b)
}

func relationshipsEqual(a, b []model.Relationship) bool {
	if len(a) != len(b) {
		return false
	}
	ax := append([]model.Relationship(nil), a...)
	bx := append([]model.Relationship(nil), b...)
	sortRel := func(r []model.Relationship) {
		sort.Slice(r, func(i, j int) bool {
			if r[i].SourceRef != r[j].SourceRef {
				return r[i].SourceRef < r[j].SourceRef
			}
			if r[i].TargetRef != r[j].TargetRef {
				return r[i].TargetRef < r[j].TargetRef
			}
			return r[i].Type < r[j].Type
		})
	}
	sortRel(ax)
	sortRel(bx)
	return reflect.DeepEqual(ax, bx)
}

func normalizeProps(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	return m
}

func normalizeStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// TestEnrichedFieldsHydrate verifies that astinus:* properties found in
// the input are projected back onto the typed Component fields and
// removed from Properties so the next write doesn't double-emit them.
func TestEnrichedFieldsHydrate(t *testing.T) {
	body := loadFixture(t, "already-enriched.cdx.json")
	sbom, err := cyclonedx.ReadJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(sbom.Components))
	}
	c := sbom.Components[0]
	if c.Origin != model.OriginApplication {
		t.Errorf("Origin = %q, want %q", c.Origin, model.OriginApplication)
	}
	if c.LayerInfo == nil {
		t.Fatal("LayerInfo should be populated from properties")
	}
	if c.LayerInfo.LayerDigest != "sha256:abc123" {
		t.Errorf("LayerDigest = %q", c.LayerInfo.LayerDigest)
	}
	if c.LayerInfo.LayerIndex != 3 {
		t.Errorf("LayerIndex = %d, want 3", c.LayerInfo.LayerIndex)
	}
	if c.LayerInfo.AddedBy != "RUN apt-get install libfoo" {
		t.Errorf("AddedBy = %q", c.LayerInfo.AddedBy)
	}
	if c.LayerInfo.DockerfileLine != "12" {
		t.Errorf("DockerfileLine = %q", c.LayerInfo.DockerfileLine)
	}
	if len(c.CPEs) != 2 {
		t.Errorf("expected 2 CPEs (primary + astinus:cpe:1), got %d: %v", len(c.CPEs), c.CPEs)
	}
	for k := range c.Properties {
		if k == model.PropertyOrigin || k == model.PropertyLayerDigest ||
			k == model.PropertyLayerIndex || k == model.PropertyLayerAddedBy ||
			k == model.PropertyLayerDockerfileLine || k == "astinus:cpe:1" {
			t.Errorf("property %q should have been consumed during hydrate", k)
		}
	}
}

// TestWriterEmitsAstinusProperties verifies that LayerInfo / Origin /
// extra CPEs set on a fresh canonical model show up in the JSON output
// as astinus:* properties.
func TestWriterEmitsAstinusProperties(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{
			{
				BOMRef: "comp-1",
				Type:   model.ComponentTypeLibrary,
				Name:   "libfoo",
				CPEs: []string{
					"cpe:2.3:a:vendor1:libfoo:1:*:*:*:*:*:*:*",
					"cpe:2.3:a:vendor2:libfoo:1:*:*:*:*:*:*:*",
				},
				LayerInfo: &model.LayerInfo{
					LayerDigest: "sha256:deadbeef",
					LayerIndex:  2,
					AddedBy:     "COPY . /app",
				},
				Origin: model.OriginApplication,
			},
		},
	}

	var buf bytes.Buffer
	if err := cyclonedx.WriteJSON(&buf, sbom, cyclonedx.WriteOptions{Pretty: true}); err != nil {
		t.Fatalf("write: %v", err)
	}

	var out struct {
		Components []struct {
			CPE        string `json:"cpe"`
			Properties []struct {
				Name, Value string
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(out.Components) != 1 {
		t.Fatalf("want 1 component in output, got %d", len(out.Components))
	}
	if got := out.Components[0].CPE; got != "cpe:2.3:a:vendor1:libfoo:1:*:*:*:*:*:*:*" {
		t.Errorf("primary CPE = %q", got)
	}
	want := map[string]string{
		"astinus:cpe:1":          "cpe:2.3:a:vendor2:libfoo:1:*:*:*:*:*:*:*",
		"astinus:layer:digest":   "sha256:deadbeef",
		"astinus:layer:index":    "2",
		"astinus:layer:added-by": "COPY . /app",
		"astinus:origin":         "app",
	}
	got := map[string]string{}
	for _, p := range out.Components[0].Properties {
		got[p.Name] = p.Value
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("property %q = %q, want %q (full set: %v)", k, got[k], v, got)
		}
	}
}

func TestReadEmptyInputErrors(t *testing.T) {
	if _, err := cyclonedx.ReadBytes(nil, model.FormatCycloneDXJSON); err == nil {
		t.Error("expected error for empty input")
	}
	if _, err := cyclonedx.ReadBytes([]byte{}, model.FormatCycloneDXJSON); err == nil {
		t.Error("expected error for empty input")
	}
}

func TestReadBytesUnsupportedFormat(t *testing.T) {
	if _, err := cyclonedx.ReadBytes([]byte("x"), model.FormatSPDXJSON); err == nil {
		t.Error("expected error for SPDX format on cyclonedx reader")
	}
}

func TestReadBytesXMLFormat(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"><components><component type="library"><name>foo</name><version>1</version></component></components></bom>`)
	sbom, err := cyclonedx.ReadBytes(xml, model.FormatCycloneDXXML)
	if err != nil {
		t.Fatalf("ReadBytes XML: %v", err)
	}
	if len(sbom.Components) != 1 || sbom.Components[0].Name != "foo" {
		t.Fatalf("unexpected components: %+v", sbom.Components)
	}
	if sbom.SourceFormat != model.FormatCycloneDXXML {
		t.Errorf("SourceFormat = %v", sbom.SourceFormat)
	}
}

func TestWriteNilSBOM(t *testing.T) {
	var buf bytes.Buffer
	if err := cyclonedx.WriteJSON(&buf, nil, cyclonedx.WriteOptions{}); err == nil {
		t.Fatal("expected error for nil sbom")
	}
}

func TestWriteJSONIsValidJSON(t *testing.T) {
	body := loadFixture(t, "syft-nginx.cdx.json")
	sbom, err := cyclonedx.ReadJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var buf bytes.Buffer
	if err := cyclonedx.WriteJSON(&buf, sbom, cyclonedx.WriteOptions{Pretty: false}); err != nil {
		t.Fatalf("write: %v", err)
	}
	var probe map[string]any
	if err := json.Unmarshal(buf.Bytes(), &probe); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if probe["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v", probe["bomFormat"])
	}
}
