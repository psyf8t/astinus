package sbom

import (
	"errors"
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
	// Truncated JSON should not crash; we return Unknown without an
	// error because the bytes simply do not satisfy a known shape.
	got, err := DetectBytes([]byte(`{"bomFormat":"CycloneDX"`)) // unterminated
	if err != nil {
		t.Fatalf("DetectBytes truncated json: %v", err)
	}
	// The Unmarshal will fail, but the bomFormat key was already
	// captured before the error occurred? Actually json.Unmarshal is
	// all-or-nothing; on truncation no field is populated -> Unknown.
	if got != model.FormatUnknown {
		t.Fatalf("truncated json should be Unknown, got %v", got)
	}
}
