//go:build acceptance

package ux

import (
	"fmt"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	s3 "github.com/psyf8t/astinus/test/acceptance/sprint3/helpers"
	s4 "github.com/psyf8t/astinus/test/acceptance/sprint4/helpers"
)

// tinyNpmSBOM materialises a CycloneDX SBOM with n npm components.
// Sprint 5's cpe-mode gates don't need to push past the NVD
// rate-limit threshold (Sprint 4 already pins that path); they
// assert the metadata STAMP shape, which is mode-driven rather
// than threshold-driven.
func tinyNpmSBOM(tb testing.TB, n int) string {
	tb.Helper()
	comps := make([]cdx.Component, 0, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("pkg-%d", i)
		comps = append(comps, cdx.Component{
			BOMRef:     "comp-" + name,
			Type:       cdx.ComponentTypeLibrary,
			Name:       name,
			Version:    "1.0.0",
			PackageURL: "pkg:npm/" + name + "@1.0.0",
		})
	}
	return s4.WriteCDXSBOM(tb, comps, cdx.Tool{Name: "syft"})
}

// TestS5T4_OfflineModeStampsReasonEncodedSkippedSources — S5 Task 4
// regression gate. ADR-0051 makes `--cpe-mode offline` enumerate
// every recognised online source under
// `astinus:cpe:sources-skipped` with the reason `:offline-mode`.
// Pre-S5 the offline path stamped an empty string (online sources
// never registered, so there was nothing to "skip") and SBOM
// consumers had to infer the intent from the mode property alone.
// This test pins:
//
//  1. `astinus:cpe:mode = offline`
//  2. `astinus:cpe:sources-skipped` contains `online-nvd:offline-mode`
//     AND `clearly-defined:offline-mode` — the reason-encoded shape.
//  3. `astinus:cpe:sources-used` is populated with at least one
//     entry (the local/offline sources that DID run).
func TestS5T4_OfflineModeStampsReasonEncodedSkippedSources(t *testing.T) {
	sbom := tinyNpmSBOM(t, 5)

	res := s3.RunEnrichOK(t, s3.EnrichOpts{
		SBOM:  sbom,
		Image: "test/empty:1",
		Extra: []string{"--cpe-mode", "offline"},
	})
	if res.BOM == nil {
		t.Fatal("no BOM in output")
	}
	if got := s4.MetadataProperty(res.BOM, "astinus:cpe:mode"); got != "offline" {
		t.Errorf("astinus:cpe:mode = %q, want offline", got)
	}

	skipped := s4.MetadataProperty(res.BOM, "astinus:cpe:sources-skipped")
	for _, want := range []string{
		"online-nvd:offline-mode",
		"clearly-defined:offline-mode",
	} {
		if !strings.Contains(skipped, want) {
			t.Errorf("astinus:cpe:sources-skipped = %q, want to include %q (S5-T4 reason-encoded contract)",
				skipped, want)
		}
	}

	used := s4.MetadataProperty(res.BOM, "astinus:cpe:sources-used")
	if used == "" {
		t.Errorf("astinus:cpe:sources-used is empty — offline mode should report the local sources that did run")
	}
}

// TestS5T4_AutoModeStampsSourcesUsedAlongsideSkipped — guards the
// ADR-0051 clause that `sources-used` is the typed companion to
// `sources-skipped`, not a replacement. In auto mode (the default)
// the binary stamps WHAT actually ran AND what got skipped (with
// reasons). A pre-S5 binary stamped only the skipped side; SBOM
// consumers building enrichment-coverage dashboards had to parse
// the `cpe.resolver.configured` log line to figure out which
// sources contributed.
func TestS5T4_AutoModeStampsSourcesUsedAlongsideSkipped(t *testing.T) {
	sbom := tinyNpmSBOM(t, 5)

	res := s3.RunEnrichOK(t, s3.EnrichOpts{
		SBOM:  sbom,
		Image: "test/empty:1",
		Extra: []string{"--cpe-mode", "auto"},
	})
	if res.BOM == nil {
		t.Fatal("no BOM in output")
	}
	if got := s4.MetadataProperty(res.BOM, "astinus:cpe:mode"); got != "auto" {
		t.Errorf("astinus:cpe:mode = %q, want auto", got)
	}
	used := s4.MetadataProperty(res.BOM, "astinus:cpe:sources-used")
	if used == "" {
		t.Errorf("astinus:cpe:sources-used is empty in auto mode — at least one source (pattern-matcher / local-dict / heuristic) must register")
	}

	// Every entry in `sources-skipped` MUST carry the reason-token
	// suffix `:<reason>` per the S5-T4 contract. Empty skipped is
	// also acceptable (a fully-online auto run skips nothing).
	skipped := s4.MetadataProperty(res.BOM, "astinus:cpe:sources-skipped")
	if skipped != "" {
		for _, entry := range strings.Split(skipped, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			if !strings.Contains(entry, ":") {
				t.Errorf("sources-skipped entry %q lacks reason suffix — pre-S5 bare-source format leaked through (%q)",
					entry, skipped)
			}
		}
	}
}

// TestS5T4_HelpTextDocumentsThreeStateContract — guards ADR-0051's
// clause that `astinus enrich --help` carries the full mode
// contract. An operator reading `--help` MUST see the offline /
// auto / hybrid descriptions and the deprecated `online` alias.
// The pre-S5 help was a one-liner pointing at `docs/configuration.md`.
func TestS5T4_HelpTextDocumentsThreeStateContract(t *testing.T) {
	bin := s3.AstinusBinary(t)
	res := runHelp(t, bin)

	for _, want := range []string{
		"offline",
		"auto",
		"hybrid",
		"online",       // deprecated alias must still be listed
		"NVD_API_KEY",  // auto-mode predicate
		"sources-used", // the typed companion stamp
	} {
		if !strings.Contains(res, want) {
			t.Errorf("--cpe-mode help text missing %q\nfull help:\n%s", want, res)
		}
	}
}
