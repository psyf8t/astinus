//go:build acceptance

package quality

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	s3 "github.com/psyf8t/astinus/test/acceptance/sprint3/helpers"
	s4 "github.com/psyf8t/astinus/test/acceptance/sprint4/helpers"
)

// TestS5T2_LayerDigestIsOCIDiffIDNotBlobHash — S5 Task 2
// regression gate. Pre-S5 the attribution enricher stamped
// `astinus:layer:digest` with the registry-blob digest
// (compressed gzip-of-tar hash). OCI rootfs identity is the
// UNCOMPRESSED tar SHA-256 (`rootfs.diff_ids[i]`), which is what
// scanners and base-image diff tools expect. ADR-0049 makes
// `astinus:layer:digest` carry the diff_id; the compressed blob
// hash moves to the companion `astinus:layer:compressed-digest`.
//
// This test drives a single-layer OCI image through the binary
// and asserts that an attributed component carries BOTH stamps
// and that they are DISTINCT — the diff_id is the uncompressed
// tar hash, the compressed-digest is the registry blob hash, and
// gzip(tar) ≠ tar for any non-degenerate input. A pre-S5 binary
// would have stamped only the latter (or, worse, populated both
// fields with the same blob hash), which both fail this check.
func TestS5T2_LayerDigestIsOCIDiffIDNotBlobHash(t *testing.T) {
	// Library-shaped ELF blob — the untracked enricher will surface
	// it as an observed-only component with full layer attribution.
	bareELF := append([]byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0, 1, 2, 3, 4},
		bytes.Repeat([]byte{0x99}, 8192)...)
	image := s4.OCIImageWithFiles(t, map[string][]byte{
		"usr/lib/libdistinct.so.1": bareELF,
	})
	emptySBOM := s4.WriteCDXSBOM(t, nil)

	res := s3.RunEnrichOK(t, s3.EnrichOpts{
		SBOM:      emptySBOM,
		Image:     image,
		NoNetwork: true,
	})
	if res.BOM == nil || res.BOM.Components == nil {
		t.Fatal("BOM has no components")
	}

	var attributed *cdx.Component
	for i := range *res.BOM.Components {
		c := &(*res.BOM.Components)[i]
		if s4.PropertyValue(c, "astinus:layer:digest") != "" {
			attributed = c
			break
		}
	}
	if attributed == nil {
		t.Fatal("no component carries astinus:layer:digest — attribution enricher did not stamp the synthetic layer")
	}

	diffID := s4.PropertyValue(attributed, "astinus:layer:digest")
	compressed := s4.PropertyValue(attributed, "astinus:layer:compressed-digest")

	if !strings.HasPrefix(diffID, "sha256:") {
		t.Errorf("astinus:layer:digest = %q, want sha256:<hex> shape", diffID)
	}
	if !strings.HasPrefix(compressed, "sha256:") {
		t.Errorf("astinus:layer:compressed-digest = %q, want sha256:<hex> shape", compressed)
	}
	if diffID == compressed {
		t.Errorf("layer:digest == layer:compressed-digest (%q) — S5-T2 split lost; "+
			"a pre-S5 binary stamped the blob hash into both slots", diffID)
	}
}

// TestS5T2_LayerDigestRoundTripsAcrossEnrich — guards the
// reader/writer pair. When Astinus reads its own output and
// re-enriches, both stamps must survive. The pre-S5 reader didn't
// know about `astinus:layer:compressed-digest`, so the second write
// would have dropped it; ADR-0049 + the mapper updates make it
// round-trip.
func TestS5T2_LayerDigestRoundTripsAcrossEnrich(t *testing.T) {
	bareELF := append([]byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0, 1, 2, 3, 4},
		bytes.Repeat([]byte{0xAA}, 8192)...)
	image := s4.OCIImageWithFiles(t, map[string][]byte{
		"usr/lib/libroundtrip.so.1": bareELF,
	})
	emptySBOM := s4.WriteCDXSBOM(t, nil)

	first := s3.RunEnrichOK(t, s3.EnrichOpts{
		SBOM:      emptySBOM,
		Image:     image,
		NoNetwork: true,
	})
	if first.BOM == nil {
		t.Fatal("first enrich produced no BOM")
	}

	// Use the first-pass output as the input to a second pass.
	second := s3.RunEnrichOK(t, s3.EnrichOpts{
		SBOM:      first.OutPath,
		Image:     image,
		NoNetwork: true,
	})
	if second.BOM == nil || second.BOM.Components == nil {
		t.Fatal("second enrich produced no BOM")
	}

	var attributed *cdx.Component
	for i := range *second.BOM.Components {
		c := &(*second.BOM.Components)[i]
		if s4.PropertyValue(c, "astinus:layer:digest") != "" {
			attributed = c
			break
		}
	}
	if attributed == nil {
		t.Fatal("round-trip: no component carries astinus:layer:digest on the second pass")
	}
	if got := s4.PropertyValue(attributed, "astinus:layer:compressed-digest"); got == "" {
		t.Errorf("round-trip: astinus:layer:compressed-digest dropped on re-read/re-write — reader hydration regression")
	}
}
