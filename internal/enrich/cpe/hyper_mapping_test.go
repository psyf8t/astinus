package cpe

import (
	"strings"
	"testing"
)

// TestBundledResolver_HyperMapsToHyperNotHyperium — Sprint 7
// Task 5. Run-2 benchmark measured the pre-S7 `hyper@1.0.0` Rust
// crate mapping as Astinus's first WORSE CPE-quality verdict
// across all benchmark runs:
//
//	Syft baseline: cpe:2.3:a:hyper:hyper:1.0.0:*:* (278 NVD matches)
//	Astinus pre-S7: cpe:2.3:a:hyperium:hyper:1.0.0:*:* (0 NVD matches)
//
// The bundled mapping was based on the GitHub org name (hyperium),
// but NVD's CPE dictionary registers the crate under
// `hyper:hyper`. The fix removes the GitHub-org heuristic for this
// specific crate. ADR-0062 amendment.
func TestBundledResolver_HyperMapsToHyperNotHyperium(t *testing.T) {
	r := NewBundledResolver()
	got := r.Resolve(PURL{Type: "cargo", Name: "hyper", Version: "1.0.0"})
	if len(got) == 0 {
		t.Fatal("hyper@1.0.0 resolved to zero candidates — bundled mapping lost")
	}
	cpe := got[0].CPE
	if strings.Contains(cpe, "hyperium") {
		t.Errorf("hyper@1.0.0 mapped to %q — still uses hyperium vendor (regression vs S7-T5)",
			cpe)
	}
	if !strings.Contains(cpe, "a:hyper:hyper:") {
		t.Errorf("hyper@1.0.0 = %q, want vendor=hyper product=hyper (NVD-canonical)", cpe)
	}
}
