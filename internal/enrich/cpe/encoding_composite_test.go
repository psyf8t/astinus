package cpe

import (
	"context"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestEnricher_NoURLPercentLeaksOnDebEpochSBOM is the Sprint 9 Task
// 1 "real-image proxy" pin. Drives the full Enricher pipeline
// against a Debian-style SBOM that mixes pre-S7 URL-percent
// encoded input CPEs (`%3A` / `%2B`) with clean spec-correct
// input CPEs, and asserts that ZERO `%xx` substrings survive into
// the output across:
//
//   - `c.CPEs[0]`  (primary)
//   - `c.CPEs[1..]` (alternatives)
//   - every `c.Properties` value (covers
//     `astinus:cpe:alternative:N`, `astinus:cpe:rejected:N`,
//     all extra CPE-bearing properties)
//   - sbom-level `Metadata.Properties` (no `%xx` should leak
//     through any aggregate stamp either)
//
// Every output CPE is also round-tripped through `IsValidCPE` to
// confirm structural validity post-normalisation.
//
// S6-T1 added `EscapeCPE23Attribute` + `cpe.Build` /
// `CPEv23.String` for the output path; S7-T1 added
// `NormalizeCPEEncoding` for the ingest path; S8-T1 added the
// count stamp. This single composite test asserts they compose
// to honour NIST IR 7695 §6.1.2.5 end-to-end.
//
// S9 Task 1 / ADR-0058 amendment.
func TestEnricher_NoURLPercentLeaksOnDebEpochSBOM(t *testing.T) {
	debEpochInputs := []struct {
		name, version, purl string
		// Mix of pre-S7 URL-percent inputs and spec-correct
		// backslash-escape inputs to cover both ingest paths.
		inputCPEs []string
	}{
		{
			"libcap2", "1:2.75-10+b8", "pkg:deb/debian/libcap2@1:2.75-10+b8",
			[]string{
				// Pre-S7 URL-percent shape (from older Syft/Trivy
				// wrappers). NormalizeCPEEncoding repairs this.
				`cpe:2.3:a:libcap2:libcap2:1%3A2.75-10%2Bb8:*:*:*:*:*:*:*`,
			},
		},
		{
			"libev4", "1:4.33-1", "pkg:deb/debian/libev4@1:4.33-1",
			[]string{
				`cpe:2.3:a:libev:libev4:1%3A4.33-1:*:*:*:*:*:*:*`,
			},
		},
		{
			"zlib1g", "1:1.3.dfsg+really1.3.1-1+b1",
			"pkg:deb/debian/zlib1g@1:1.3.dfsg+really1.3.1-1+b1",
			[]string{
				// Already spec-correct — passthrough; output must
				// still carry zero `%xx`.
				`cpe:2.3:a:zlib1g:zlib1g:1\:1.3.dfsg\+really1.3.1-1\+b1:*:*:*:*:*:*:*`,
			},
		},
		{
			"diffutils", "1:3.8-4", "pkg:deb/debian/diffutils@1:3.8-4",
			[]string{
				`cpe:2.3:a:diffutils:diffutils:1%3A3.8-4:*:*:*:*:*:*:*`,
			},
		},
		// Non-deb baseline — no special chars in version, no
		// transform should happen, no leak.
		{
			"openssl", "3.0.0", "pkg:deb/debian/openssl@3.0.0",
			[]string{
				`cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*`,
			},
		},
	}

	comps := make([]model.Component, 0, len(debEpochInputs))
	for _, in := range debEpochInputs {
		comps = append(comps, model.Component{
			Name:    in.name,
			Version: in.version,
			PURL:    in.purl,
			CPEs:    in.inputCPEs,
		})
	}
	sbom := &model.SBOM{Components: comps}

	e := New()
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich err = %v, want nil", err)
	}

	for i := range sbom.Components {
		c := &sbom.Components[i]

		// Primary + alternative CPEs on the Component itself.
		for _, cpe := range c.CPEs {
			assertNoPercentLeak(t, "c.CPEs", c.Name, cpe)
			assertValidCPE(t, "c.CPEs", c.Name, cpe)
		}

		// Every property whose value looks like a CPE 2.3 URI —
		// covers the `astinus:cpe:alternative:N` / `:rejected:N`
		// families and any other extra-CPE property a future
		// writer might add. Filtering by the `cpe:2.3:` prefix
		// keeps the assertion focused (the metadata side carries
		// non-CPE properties too).
		for key, value := range c.Properties {
			if !strings.HasPrefix(value, "cpe:2.3:") {
				continue
			}
			assertNoPercentLeak(t, "c.Properties["+key+"]", c.Name, value)
			assertValidCPE(t, "c.Properties["+key+"]", c.Name, value)
		}
	}

	// SBOM-level metadata stamps — total-cap-configured /
	// source-status / etc — must not leak either, even though
	// these are not CPE URIs themselves; they form the operator's
	// rendering of the run.
	for key, value := range sbom.Metadata.Properties {
		if !strings.HasPrefix(value, "cpe:2.3:") {
			continue
		}
		assertNoPercentLeak(t, "sbom.Metadata.Properties["+key+"]", "sbom", value)
	}

	// S8-T1 normalisation count stamp must report the 3 inputs
	// that carried URL-percent encoding (libcap2, libev4,
	// diffutils — zlib1g is already spec-correct, openssl is
	// plain).
	got := sbom.Metadata.Properties[model.PropertyCPEInputNormalisedCount]
	if got != "3" {
		t.Errorf("%s = %q, want %q (3 of the 5 inputs needed repair)",
			model.PropertyCPEInputNormalisedCount, got, "3")
	}
}

func assertNoPercentLeak(t *testing.T, where, comp, cpe string) {
	t.Helper()
	for _, bad := range []string{"%3A", "%2B", "%40", "%5C", "%3F", "%2F"} {
		if strings.Contains(strings.ToUpper(cpe), bad) {
			t.Errorf("%s for %q leaked %q in %q — output side must emit backslash-escape per NIST IR 7695",
				where, comp, bad, cpe)
		}
	}
}

func assertValidCPE(t *testing.T, where, comp, cpe string) {
	t.Helper()
	if !IsValidCPE(cpe) {
		t.Errorf("%s for %q produced invalid CPE 2.3: %q", where, comp, cpe)
	}
}
