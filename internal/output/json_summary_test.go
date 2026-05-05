package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestSummaryRendererBasic(t *testing.T) {
	r, err := Get(FormatSummary, Options{})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if r.Name() != FormatSummary {
		t.Errorf("Name = %q", r.Name())
	}
	if r.MIMEType() != "text/plain" {
		t.Errorf("MIMEType = %q", r.MIMEType())
	}

	sbom := &model.SBOM{
		Metadata: model.Metadata{Component: &model.Component{
			BOMRef: "img", Name: "myapp", Version: "1.2.3",
			Hashes: []model.Hash{{Algorithm: model.HashAlgorithmSHA256, Value: "abc123def456000000000000000000000000000000000000000000000000aaaa"}},
		}},
		Components: []model.Component{
			{BOMRef: "1", Name: "musl", Version: "1.2", Origin: model.OriginBaseImage,
				CPEs: []string{"cpe:2.3:a:musl-libc:musl:1.2:*:*:*:*:*:*:*"}},
			{BOMRef: "2", Name: "myapp", Version: "1.0", Origin: model.OriginApplication,
				CPEs:       []string{"cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"},
				Properties: map[string]string{"astinus:cpe:source": "bundled", "astinus:cpe:confidence": "high"}},
			{BOMRef: "3", Name: "ghost", Origin: model.OriginUnknown},
			{
				BOMRef: "4", Name: "jq", Version: "1.7.1",
				Hashes: []model.Hash{{Algorithm: model.HashAlgorithmSHA256, Value: "deadbeef000000000000000000000000000000000000000000000000beef0000"}},
				Evidence: &model.Evidence{
					Method:    "fingerprint",
					Locations: []model.EvidenceLocation{{Path: "/usr/local/bin/jq"}},
				},
				Properties: map[string]string{"astinus:untracked:category": "executable"},
			},
			{
				BOMRef: "5", Name: "legacy.jar",
				Hashes: []model.Hash{{Algorithm: model.HashAlgorithmSHA256, Value: "1234567890ab1234567890ab1234567890ab1234567890ab1234567890ab1234"}},
				Evidence: &model.Evidence{
					Method:    "untracked-scan",
					Locations: []model.EvidenceLocation{{Path: "/opt/myapp/lib/legacy.jar"}},
				},
				Properties: map[string]string{"astinus:untracked:category": "archive"},
			},
		},
	}

	var buf bytes.Buffer
	if err := r.Render(&buf, sbom); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Image:  myapp@1.2.3",
		"Digest: sha256:abc123def456",
		"Component summary:",
		"Total:           5",
		"From base:       1",
		"Application:     1",
		"Unknown origin:  1",
		"Untracked added: 2",
		"Untracked findings:",
		"! /usr/local/bin/jq",         // fingerprint marker
		"? /opt/myapp/lib/legacy.jar", // untracked-only marker
		"CPE enrichment:",
		"Components with CPE: 2/5",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

func TestSummaryRendererWithoutMetadata(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{Name: "x"}}}
	r, _ := Get(FormatSummary, Options{})
	var buf bytes.Buffer
	if err := r.Render(&buf, sbom); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "(not declared in SBOM metadata)") {
		t.Errorf("expected 'not declared' fallback:\n%s", buf.String())
	}
}

func TestSummaryRendererNilSBOM(t *testing.T) {
	r, _ := Get(FormatSummary, Options{})
	if err := r.Render(&bytes.Buffer{}, nil); err == nil {
		t.Fatal("expected error for nil sbom")
	}
}

func TestSummaryEmptyComponents(t *testing.T) {
	sbom := &model.SBOM{
		Metadata: model.Metadata{Component: &model.Component{Name: "img"}},
	}
	r, _ := Get(FormatSummary, Options{})
	var buf bytes.Buffer
	_ = r.Render(&buf, sbom)
	if !strings.Contains(buf.String(), "Total:           0") {
		t.Errorf("got:\n%s", buf.String())
	}
}

func TestTruncateHelper(t *testing.T) {
	if truncate("abcdef", 3) != "abc" {
		t.Error("truncate longer")
	}
	if truncate("ab", 5) != "ab" {
		t.Error("truncate shorter (no-op)")
	}
}
