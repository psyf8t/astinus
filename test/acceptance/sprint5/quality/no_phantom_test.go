//go:build acceptance

package quality

import (
	"bytes"
	"strings"
	"testing"

	s3 "github.com/psyf8t/astinus/test/acceptance/sprint3/helpers"
	s4 "github.com/psyf8t/astinus/test/acceptance/sprint4/helpers"
)

// TestS5T1_LibraryShapedPathsSurfaceAsObservedOnly — S5 Task 1
// regression gate, the Sprint-5 sibling of S4-T0's no-phantom
// test. Run #3 on the pinned Grafana digest measured ~60
// `pkg:generic/<sonamename>` rows produced by the ELF extractor's
// DT_SONAME path (libcrypto.so → "crypto", libcurl.so → "curl",
// libcap.so → "cap", …). ADR-0048 collapses the extractor to
// return empty Identity unconditionally — library-shaped ELF
// files now fall through to the untracked enricher's observed-only
// shape (Type=file, no PURL, no CPE, `astinus:evidence-level =
// observed`).
//
// The S4-T0 / S5-T1 sibling in `sprint4/quality/no_phantom_test.go`
// drives the same scenario from the Sprint-4 vantage. This file
// re-pins the contract from the Sprint-5 vantage with a broader
// library-shaped fixture set (the Run #3 SONAME victim list) so a
// future regression that re-introduces ANY SONAME-derived
// synthesis in the extractor breaks here even if the S4 test was
// silently weakened.
func TestS5T1_LibraryShapedPathsSurfaceAsObservedOnly(t *testing.T) {
	bareELF := append([]byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0, 1, 2, 3, 4},
		bytes.Repeat([]byte{0x55}, 8192)...)
	image := s4.OCIImageWithFiles(t, map[string][]byte{
		"usr/lib/libcrypto.so.3":       bareELF,
		"usr/lib/libssl.so.3":          bareELF,
		"usr/lib/libcurl.so.4":         bareELF,
		"usr/lib/libcap.so.2":          bareELF,
		"usr/lib/libcares.so.2":        bareELF,
		"usr/lib/libbrotlicommon.so.1": bareELF,
		"usr/lib/libbrotlidec.so.1":    bareELF,
		"usr/lib/libiconv.so.2":        bareELF,
	})
	emptySBOM := s4.WriteCDXSBOM(t, nil)

	res := s3.RunEnrichOK(t, s3.EnrichOpts{
		SBOM:      emptySBOM,
		Image:     image,
		NoNetwork: true,
	})
	if res.BOM == nil || res.BOM.Components == nil {
		t.Fatal("BOM has no components — enrichment produced nothing")
	}

	// The Run-#3 SONAME victim list. The ELF extractor pre-S5
	// stamped each of these as a `pkg:generic/<name>` row; the S5
	// fix MUST keep them off the SBOM with a generic PURL.
	forbiddenSONAMENames := []string{
		"crypto", "ssl", "curl",
		"cap", "cares",
		"brotlicommon", "brotlidec", "iconv",
	}

	var observed int
	for _, c := range *res.BOM.Components {
		if c.PackageURL != "" {
			for _, bad := range forbiddenSONAMENames {
				want := "pkg:generic/" + bad
				if c.PackageURL == want || strings.HasPrefix(c.PackageURL, want+"@") {
					t.Errorf("SONAME-derived phantom leaked: name=%s purl=%s "+
						"(S5-T1 extractor regression — ADR-0048)",
						c.Name, c.PackageURL)
				}
			}
		}
		if c.CPE != "" {
			// Library-shaped paths must also keep their hands off
			// the scanner-facing CPE field — that's the whole point
			// of S4-T0 + S5-T1 working together.
			t.Errorf("scanner-facing CPE on observed-only row %s: %q", c.Name, c.CPE)
		}
		if s4.PropertyValue(&c, "astinus:evidence-level") == "observed" {
			observed++
		}
	}
	if observed == 0 {
		t.Errorf("no observed-only components in output; got %d total — library files vanished entirely instead of surfacing as observed",
			len(*res.BOM.Components))
	}
}
