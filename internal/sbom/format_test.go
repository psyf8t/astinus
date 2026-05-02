package sbom

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestDetectBytes(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  model.Format
	}{
		{
			name:  "cyclonedx-json",
			input: `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`,
			want:  model.FormatCycloneDXJSON,
		},
		{
			name:  "cyclonedx-json-case-insensitive",
			input: `{"bomFormat":"cyclonedx","specVersion":"1.5"}`,
			want:  model.FormatCycloneDXJSON,
		},
		{
			name:  "spdx-json",
			input: `{"spdxVersion":"SPDX-2.3","name":"x","SPDXID":"SPDXRef-DOCUMENT"}`,
			want:  model.FormatSPDXJSON,
		},
		{
			name:  "cyclonedx-xml",
			input: `<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6"></bom>`,
			want:  model.FormatCycloneDXXML,
		},
		{
			name:  "spdx-tag-value",
			input: "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\n",
			want:  model.FormatSPDXTagValue,
		},
		{
			name:  "spdx-tag-value-with-leading-whitespace",
			input: "\n\t SPDXVersion: SPDX-2.3\n",
			want:  model.FormatSPDXTagValue,
		},
		{
			name:  "unknown-json",
			input: `{"foo":"bar"}`,
			want:  model.FormatUnknown,
		},
		{
			name:  "unknown-xml",
			input: `<?xml version="1.0"?><other></other>`,
			want:  model.FormatUnknown,
		},
		{
			name:  "unknown-text",
			input: "not an SBOM\n",
			want:  model.FormatUnknown,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := DetectBytes([]byte(c.input))
			if err != nil {
				t.Fatalf("DetectBytes() unexpected error: %v", err)
			}
			if got != c.want {
				t.Fatalf("DetectBytes() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestDetectBytesEmpty(t *testing.T) {
	for _, in := range []string{"", "   ", "\t\n  \r\n"} {
		_, err := DetectBytes([]byte(in))
		if !errors.Is(err, ErrEmptyInput) {
			t.Fatalf("DetectBytes(%q) error = %v, want ErrEmptyInput", in, err)
		}
	}
}

func TestDetectFromReader(t *testing.T) {
	const input = `{"bomFormat":"CycloneDX","specVersion":"1.6"}`
	format, body, err := Detect(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Detect() unexpected error: %v", err)
	}
	if format != model.FormatCycloneDXJSON {
		t.Fatalf("Detect() format = %v, want CycloneDXJSON", format)
	}
	if string(body) != input {
		t.Fatalf("Detect() body = %q, want %q", string(body), input)
	}
}

func TestDetectMalformedJSON(t *testing.T) {
	// Truncated JSON should not crash. With the streaming decoder
	// (ADR-0016) the format-defining key/value pair is captured the
	// moment it parses cleanly, even when the surrounding braces are
	// not yet closed. So the input below — bomFormat fully read,
	// closing brace missing — is detected correctly.
	got, err := DetectBytes([]byte(`{"bomFormat":"CycloneDX"`))
	if err != nil {
		t.Fatalf("DetectBytes truncated json: %v", err)
	}
	if got != model.FormatCycloneDXJSON {
		t.Fatalf("truncated-after-bomFormat should be CycloneDXJSON, got %v", got)
	}
}

// TestDetectJSON_MinifiedCycloneDXLargerThanPeekLimit is the regression
// test for the Stage-1 detectJSON bug fixed in ADR-0016. Before the
// fix Astinus returned `unrecognised format` on real-world Syft 1.34
// minified output (~2 MiB single-line JSON) because json.Unmarshal
// was not tolerant of the peek window cutoff.
func TestDetectJSON_MinifiedCycloneDXLargerThanPeekLimit(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "test", "fixtures",
		"sboms", "syft-1.34-large-minified.cdx.json")
	body, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if len(body) <= peekLimit {
		t.Fatalf("fixture must exceed peekLimit (%d) to test this bug; got %d bytes",
			peekLimit, len(body))
	}

	got, err := DetectBytes(body)
	if err != nil {
		t.Fatalf("DetectBytes: %v", err)
	}
	if got != model.FormatCycloneDXJSON {
		t.Fatalf("got %v, want CycloneDXJSON (Syft 1.34 minified)", got)
	}
}

// TestDetectJSON_BomFormatNotFirst — order of top-level keys must not
// matter. Real producers (cdxgen, Trivy) sometimes emit `$schema` or
// `serialNumber` ahead of `bomFormat`.
func TestDetectJSON_BomFormatNotFirst(t *testing.T) {
	body := []byte(`{
		"$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
		"serialNumber": "urn:uuid:abc",
		"version": 1,
		"metadata": {"timestamp": "2026-01-01T00:00:00Z"},
		"bomFormat": "CycloneDX",
		"specVersion": "1.6"
	}`)
	got, err := DetectBytes(body)
	if err != nil {
		t.Fatalf("DetectBytes: %v", err)
	}
	if got != model.FormatCycloneDXJSON {
		t.Errorf("got %v, want CycloneDXJSON", got)
	}
}

// TestDetectJSON_DeeplyNestedMetadataBeforeBomFormat exercises
// skipJSONValue's recursion: a nested metadata block of objects +
// arrays must be skipped cleanly before the detector reaches
// bomFormat.
func TestDetectJSON_DeeplyNestedMetadataBeforeBomFormat(t *testing.T) {
	body := []byte(`{
		"metadata": {
			"tools": {"components": [{"name": "syft", "version": "1.34"}]},
			"component": {"type": "container", "name": "x"}
		},
		"bomFormat": "CycloneDX",
		"specVersion": "1.6"
	}`)
	got, err := DetectBytes(body)
	if err != nil {
		t.Fatalf("DetectBytes: %v", err)
	}
	if got != model.FormatCycloneDXJSON {
		t.Errorf("got %v, want CycloneDXJSON", got)
	}
}

// TestDetectJSON_SPDXMinifiedLarge synthesises a minified SPDX JSON
// document that exceeds the peek window so the SPDX side gets the
// same regression coverage as CycloneDX.
func TestDetectJSON_SPDXMinifiedLarge(t *testing.T) {
	body := buildLargeSPDXMinified(t)
	if len(body) <= peekLimit {
		t.Fatalf("synthesised fixture must exceed peekLimit")
	}
	got, err := DetectBytes(body)
	if err != nil {
		t.Fatalf("DetectBytes: %v", err)
	}
	if got != model.FormatSPDXJSON {
		t.Errorf("got %v, want SPDXJSON", got)
	}
}

// TestDetectJSON_TruncatedAtBomFormatValue: when the cutoff falls
// INSIDE the bomFormat value the decoder cannot read a complete
// token, so the format must remain Unknown.
func TestDetectJSON_TruncatedAtBomFormatValue(t *testing.T) {
	body := []byte(`{"bomFormat":"Cyclo`)
	got, err := DetectBytes(body)
	if err != nil {
		t.Fatalf("DetectBytes: %v", err)
	}
	if got != model.FormatUnknown {
		t.Errorf("got %v, want Unknown (truncated mid-value)", got)
	}
}

// TestDetectJSON_NoFormatFields: a perfectly valid JSON object with
// no SBOM-shaped keys must NOT misdetect.
func TestDetectJSON_NoFormatFields(t *testing.T) {
	body := []byte(`{"foo": "bar", "baz": [1, 2, 3]}`)
	got, err := DetectBytes(body)
	if err != nil {
		t.Fatalf("DetectBytes: %v", err)
	}
	if got != model.FormatUnknown {
		t.Errorf("got %v, want Unknown", got)
	}
}

// buildLargeSPDXMinified synthesises an SPDX 2.3 JSON document that
// exceeds peekLimit when minified, with `spdxVersion` placed FIRST
// so the streaming detector finds it but the document keeps growing
// past the cutoff to exercise the truncation path.
func buildLargeSPDXMinified(t *testing.T) []byte {
	t.Helper()
	var b strings.Builder
	b.WriteString(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"big","packages":[`)
	const filler = `{"name":"pkg","SPDXID":"SPDXRef-pkg","versionInfo":"1.0","downloadLocation":"NOASSERTION","filesAnalyzed":false},`
	// Fill until well past peekLimit.
	for b.Len() < peekLimit*2 {
		b.WriteString(filler)
	}
	// Strip trailing comma + close arrays/objects to keep the JSON
	// at least syntactically intact (tests still want to catch the
	// case when the format key is the FIRST thing seen).
	out := strings.TrimSuffix(b.String(), ",")
	out += `]}`
	return []byte(out)
}
