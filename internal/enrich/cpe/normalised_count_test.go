package cpe

import (
	"context"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestEnricher_StampsNormalisedCount — S8 Task 1. Every Enrich call
// stamps `astinus:cpe:input-normalised-count` so operators can see
// how many input CPEs the §6.1.2.5 backslash-escape normaliser
// repaired during the run. Two non-spec inputs (Debian-style epoch
// `%3A` + `%2B`) on a single component → count == 2.
// ADR-0058 amendment.
func TestEnricher_StampsNormalisedCount(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{
			{
				Name: "libcap2",
				PURL: "pkg:deb/debian/libcap2@1:2.75-10+b8",
				CPEs: []string{
					`cpe:2.3:a:libcap2:libcap2:1%3A2.75-10%2Bb8:*:*:*:*:*:*:*`,
				},
			},
			{
				Name: "libev4",
				PURL: "pkg:deb/debian/libev4@1:4.33-1",
				CPEs: []string{
					`cpe:2.3:a:libev:libev4:1%3A4.33-1:*:*:*:*:*:*:*`,
				},
			},
			{
				Name: "openssl",
				PURL: "pkg:deb/debian/openssl@3.0.0",
				CPEs: []string{
					`cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*`,
				},
			},
		},
	}
	e := New()
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	got := sbom.Metadata.Properties[model.PropertyCPEInputNormalisedCount]
	if got != "2" {
		t.Errorf("%s = %q, want %q", model.PropertyCPEInputNormalisedCount, got, "2")
	}
}

// TestEnricher_StampsNormalisedCountZero — clean input (no
// URL-percent triplets) reports a "0" rather than omitting the
// stamp. The distinction matters: absence means the enricher never
// ran, "0" means it ran and didn't need to repair anything.
func TestEnricher_StampsNormalisedCountZero(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{
			{
				Name: "openssl",
				PURL: "pkg:deb/debian/openssl@3.0.0",
				CPEs: []string{
					`cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*`,
				},
			},
		},
	}
	e := New()
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	got, ok := sbom.Metadata.Properties[model.PropertyCPEInputNormalisedCount]
	if !ok {
		t.Fatalf("%s missing on a clean run, want present-with-value-0", model.PropertyCPEInputNormalisedCount)
	}
	if got != "0" {
		t.Errorf("%s = %q, want %q", model.PropertyCPEInputNormalisedCount, got, "0")
	}
}
