package spdx_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/cyclonedx"
	"github.com/psyf8t/astinus/internal/sbom/model"
	"github.com/psyf8t/astinus/internal/sbom/spdx"
)

const fixtureDir = "../../../test/fixtures/sboms/spdx"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return body
}

// TestRoundTripJSONFixtures: SPDX → model → SPDX → model → semantic
// equivalence on the components canonical fields care about.
func TestRoundTripJSONFixtures(t *testing.T) {
	for _, name := range []string{"syft-alpine.spdx.json", "already-enriched.spdx.json"} {
		t.Run(name, func(t *testing.T) {
			body := loadFixture(t, name)

			first, err := spdx.ReadJSON(bytes.NewReader(body))
			if err != nil {
				t.Fatalf("first read: %v", err)
			}
			if first.SourceFormat != model.FormatSPDXJSON {
				t.Errorf("SourceFormat = %v", first.SourceFormat)
			}

			var out bytes.Buffer
			if err := spdx.WriteJSON(&out, first, spdx.WriteOptions{Pretty: true}); err != nil {
				t.Fatalf("write: %v", err)
			}

			second, err := spdx.ReadJSON(bytes.NewReader(out.Bytes()))
			if err != nil {
				t.Fatalf("re-read: %v", err)
			}
			assertComponentsEquivalent(t, first.Components, second.Components)
		})
	}
}

func TestEnrichedFieldsHydrate(t *testing.T) {
	body := loadFixture(t, "already-enriched.spdx.json")
	sbom, err := spdx.ReadJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("components = %d", len(sbom.Components))
	}
	c := sbom.Components[0]
	if c.Origin != model.OriginApplication {
		t.Errorf("Origin = %q", c.Origin)
	}
	if c.LayerInfo == nil {
		t.Fatal("LayerInfo should be hydrated")
	}
	if c.LayerInfo.LayerDigest != "sha256:abc123" {
		t.Errorf("LayerDigest = %q", c.LayerInfo.LayerDigest)
	}
	if c.LayerInfo.LayerIndex != 3 {
		t.Errorf("LayerIndex = %d", c.LayerInfo.LayerIndex)
	}
	if c.LayerInfo.AddedBy != "RUN apt-get install libfoo" {
		t.Errorf("AddedBy = %q", c.LayerInfo.AddedBy)
	}
	if c.PURL == "" {
		t.Error("PURL should be parsed from external refs")
	}
	if len(c.CPEs) != 1 {
		t.Errorf("CPEs = %v", c.CPEs)
	}
}

func TestWriterEmitsAstinusAnnotations(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef:  "comp-x",
			Name:    "x",
			Version: "1",
			Origin:  model.OriginBaseImage,
			LayerInfo: &model.LayerInfo{
				LayerDigest: "sha256:beef",
				LayerIndex:  1,
				AddedBy:     "FROM alpine",
			},
		}},
	}
	var buf bytes.Buffer
	if err := spdx.WriteJSON(&buf, sbom, spdx.WriteOptions{Pretty: true}); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`"comment": "astinus:layer:digest=sha256:beef"`,
		`"comment": "astinus:layer:index=1"`,
		`"comment": "astinus:layer:added-by=FROM alpine"`,
		`"comment": "astinus:origin=base"`,
	} {
		if !bytes.Contains(buf.Bytes(), []byte(want)) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
}

func TestCrossFormatCDXToSPDX(t *testing.T) {
	cdx := []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "bom-ref": "comp-1",
      "type": "library",
      "name": "express",
      "version": "4.18.2",
      "purl": "pkg:npm/express@4.18.2",
      "cpe": "cpe:2.3:a:expressjs:express:4.18.2:*:*:*:*:*:*:*",
      "hashes": [{"alg":"SHA-256","content":"deadbeefdeadbeefdeadbeefdeadbeef"}]
    }
  ]
}`)
	sbom, err := cyclonedx.ReadJSON(bytes.NewReader(cdx))
	if err != nil {
		t.Fatalf("read cdx: %v", err)
	}

	var out bytes.Buffer
	if err := spdx.WriteJSON(&out, sbom, spdx.WriteOptions{Pretty: true}); err != nil {
		t.Fatalf("write spdx: %v", err)
	}

	for _, want := range []string{
		`"name": "express"`,
		`"versionInfo": "4.18.2"`,
		`"referenceLocator": "pkg:npm/express@4.18.2"`,
		`"referenceLocator": "cpe:2.3:a:expressjs:express:4.18.2:*:*:*:*:*:*:*"`,
		`"checksumValue": "deadbeefdeadbeefdeadbeefdeadbeef"`,
	} {
		if !bytes.Contains(out.Bytes(), []byte(want)) {
			t.Errorf("output missing %q\n%s", want, out.String())
		}
	}

	// And it should round-trip back into the canonical model.
	roundTrip, err := spdx.ReadJSON(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(roundTrip.Components) != 1 || roundTrip.Components[0].Name != "express" {
		t.Errorf("round-trip components = %+v", roundTrip.Components)
	}
}

func TestReadEmptyInputErrors(t *testing.T) {
	if _, err := spdx.ReadBytes(nil, model.FormatSPDXJSON); err == nil {
		t.Error("expected error for empty input")
	}
	if _, err := spdx.ReadBytes([]byte{}, model.FormatSPDXTagValue); err == nil {
		t.Error("expected error for empty input")
	}
}

func TestReadBytesUnsupportedFormat(t *testing.T) {
	if _, err := spdx.ReadBytes([]byte("x"), model.FormatCycloneDXJSON); err == nil {
		t.Error("expected error for non-SPDX format")
	}
}

func TestReadBytesMalformedJSON(t *testing.T) {
	_, err := spdx.ReadBytes([]byte("{not json"), model.FormatSPDXJSON)
	if err == nil {
		t.Fatal("expected decode error")
	}
	if errors.Is(err, spdx.ErrEmptyInput) {
		t.Errorf("malformed JSON should not be ErrEmptyInput")
	}
}

func TestWriteJSONNilSBOM(t *testing.T) {
	if err := spdx.WriteJSON(&bytes.Buffer{}, nil, spdx.WriteOptions{}); err == nil {
		t.Fatal("expected error for nil sbom")
	}
}

func TestWriteTagValueRoundTrip(t *testing.T) {
	body := loadFixture(t, "syft-alpine.spdx.json")
	sbom, err := spdx.ReadJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var buf bytes.Buffer
	if err := spdx.WriteTagValue(&buf, sbom, spdx.WriteOptions{}); err != nil {
		t.Fatalf("write tag-value: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("tag-value output empty")
	}
	roundTrip, err := spdx.ReadTagValue(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("read tag-value: %v", err)
	}
	if len(roundTrip.Components) == 0 {
		t.Errorf("tag-value round-trip lost components: %+v", roundTrip)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────

func assertComponentsEquivalent(t *testing.T, a, b []model.Component) {
	t.Helper()
	if len(a) != len(b) {
		t.Fatalf("component count: %d vs %d", len(a), len(b))
	}
	sort.Slice(a, func(i, j int) bool { return a[i].Name < a[j].Name })
	sort.Slice(b, func(i, j int) bool { return b[i].Name < b[j].Name })
	for i := range a {
		if a[i].Name != b[i].Name {
			t.Errorf("name mismatch: %q vs %q", a[i].Name, b[i].Name)
		}
		if a[i].Version != b[i].Version {
			t.Errorf("%q version: %q vs %q", a[i].Name, a[i].Version, b[i].Version)
		}
		if a[i].PURL != b[i].PURL {
			t.Errorf("%q PURL: %q vs %q", a[i].Name, a[i].PURL, b[i].PURL)
		}
		if !reflect.DeepEqual(a[i].CPEs, b[i].CPEs) {
			t.Errorf("%q CPEs: %v vs %v", a[i].Name, a[i].CPEs, b[i].CPEs)
		}
		if !reflect.DeepEqual(a[i].LayerInfo, b[i].LayerInfo) {
			t.Errorf("%q LayerInfo: %+v vs %+v", a[i].Name, a[i].LayerInfo, b[i].LayerInfo)
		}
		if a[i].Origin != b[i].Origin {
			t.Errorf("%q Origin: %q vs %q", a[i].Name, a[i].Origin, b[i].Origin)
		}
	}
}
