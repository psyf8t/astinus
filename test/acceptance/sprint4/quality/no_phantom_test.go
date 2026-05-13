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

// TestS4T0_NoPhantomComponentsFromBareELF — S4 Task 0 regression
// gate. The pre-S4 untracked enricher synthesised
// `pkg:generic/<basename>` components for stripped ELF binaries
// that the multi-modal extractor registry couldn't identify (e.g.
// busybox symlinks on real images), then the CPE chain attached
// `vendor=product=name` CPEs to those phantoms and downstream
// vulnerability scanners reported CVEs that didn't apply to the
// image at all. ADR-0038 documents the fix.
//
// This test drives the busybox-symlink reproducer through the
// actual astinus binary and asserts the output SBOM contains no
// phantom `pkg:generic/...` components, no `PURL-shape guess`
// evidence string, and that bare-ELF files surface as observed-only
// components (Type=file, no PURL/CPE, evidence-level=observed).
func TestS4T0_NoPhantomComponentsFromBareELF(t *testing.T) {
	// A bare ELF blob padded out past the matcher's MinFileBytes
	// floor so the untracked enricher actually runs the extractor
	// registry against it. Tar header magic is the only ELF signal —
	// no SONAME, no Go buildinfo, no Rust auditable section, no
	// version string in .rodata.
	bareELF := append([]byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0, 1, 2, 3, 4},
		bytes.Repeat([]byte{0x42}, 8192)...)
	image := s4.OCIImageWithFiles(t, map[string][]byte{
		// busybox-symlink-style filenames the pre-S4 path picked up
		// as phantom names. None should leak into the SBOM as
		// `pkg:generic/<basename>` rows.
		"usr/bin/busybox":          bareELF,
		"usr/local/bin/crypto":     bareELF,
		"usr/local/bin/c_rehash":   bareELF,
		"usr/local/bin/myfakebash": bareELF,
	})
	emptySBOM := s4.WriteCDXSBOM(t, nil)

	res := s3.RunEnrichOK(t, s3.EnrichOpts{
		SBOM:      emptySBOM,
		Image:     image,
		NoNetwork: true, // hermetic — no online CPE / registry lookups
	})
	if res.BOM == nil || res.BOM.Components == nil {
		t.Fatal("BOM has no components — enrichment produced nothing")
	}

	for _, c := range *res.BOM.Components {
		if c.PackageURL != "" && strings.HasPrefix(c.PackageURL, "pkg:generic/") {
			t.Errorf("phantom PURL leaked: name=%s purl=%s version=%s",
				c.Name, c.PackageURL, c.Version)
		}
		if c.CPE != "" {
			// Bare-ELF components must have NO CPE — the heuristic
			// resolver upstream was the source of the false-positive
			// CPE chain pre-S4.
			t.Errorf("CPE leaked on observed component %s: %q", c.Name, c.CPE)
		}
		if c.Properties != nil {
			for _, p := range *c.Properties {
				if p.Value == "PURL-shape guess" {
					t.Errorf("PURL-shape guess evidence resurfaced on %s: %s=%s",
						c.Name, p.Name, p.Value)
				}
			}
		}
	}

	// At least one observed-only component must surface from the
	// fixture — that's the actual operator-visible signal post-S4.
	var observed int
	for _, c := range *res.BOM.Components {
		if s4.PropertyValue(&c, "astinus:evidence-level") == "observed" {
			observed++
		}
	}
	if observed == 0 {
		t.Errorf("no observed-only components in output; got %d total components",
			len(*res.BOM.Components))
	}
}

// TestS5T1_NoSONAMEDerivedPhantoms — Sprint 5 Task 1 regression
// gate. ADR-0038 (S4 Task 0) dropped the basename fallback in the
// ELF extractor but kept DT_SONAME as the one ELF identity signal
// worth trusting. Run #3 on a real Grafana image proved that
// assumption wrong: `libcrypto.so` → SONAME → `crypto` etc.
// produced ~60 `pkg:generic/<sonamename>` rows that don't match
// anything in NVD and dropped `addition_precision` to 0.42. S5
// Task 1 (ADR-0048) makes the ELF extractor return empty Identity
// unconditionally; library-shaped paths now surface as
// observed-only.
//
// This acceptance test drives library-shaped filenames through the
// binary and asserts none of the run-#3 SONAME-derived phantoms
// (`crypto`, `cap`, `cares`, `brotlicommon`, `brotlidec`, `iconv`,
// `curl`) appear with `pkg:generic/<name>` PURL.
func TestS5T1_NoSONAMEDerivedPhantoms(t *testing.T) {
	// Same bare-ELF body the S4-T0 test uses — `buildMinimalELF`
	// produces no `.dynamic` section so DT_SONAME is empty for
	// these inputs. The S5 fix makes the contract broader (no
	// Identity even with SONAME), so the synthetic shape we can
	// build today already exercises the production path. The
	// real-image follow-up (the Sprint-5-Task-5 pinned-Grafana
	// gate) will drive the SONAME-bearing case.
	bareELF := append([]byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0, 1, 2, 3, 4},
		bytes.Repeat([]byte{0x42}, 8192)...)
	image := s4.OCIImageWithFiles(t, map[string][]byte{
		// Library-shaped filenames that would historically have
		// surfaced as `pkg:generic/<sonamename>` via the SONAME
		// path. The `usr/lib/lib*.so.*` shape mirrors real Alpine
		// layouts; pre-S5 the ELF extractor would have stamped
		// these with synthesised Identity, post-S5 they fall to
		// observed-only.
		"usr/lib/libcrypto.so.3":       bareELF,
		"usr/lib/libcap.so.2":          bareELF,
		"usr/lib/libcares.so.2":        bareELF,
		"usr/lib/libbrotlicommon.so.1": bareELF,
		"usr/lib/libbrotlidec.so.1":    bareELF,
		"usr/lib/libiconv.so.2":        bareELF,
		"usr/lib/libcurl.so.4":         bareELF,
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

	// The known SONAME-derived phantom set from the run-#3
	// metrics.json. Any of these surfacing under
	// `pkg:generic/<name>` is a regression to the pre-S5 contract.
	forbiddenNames := []string{
		"crypto", "cap", "cares",
		"brotlicommon", "brotlidec",
		"iconv", "curl",
	}
	for _, c := range *res.BOM.Components {
		if c.PackageURL == "" {
			continue
		}
		for _, bad := range forbiddenNames {
			want := "pkg:generic/" + bad
			if c.PackageURL == want || strings.HasPrefix(c.PackageURL, want+"@") {
				t.Errorf("SONAME-derived phantom leaked: name=%s purl=%s",
					c.Name, c.PackageURL)
			}
		}
	}
}

// TestS4T3_GolangCPEsLandAsEvidenceOnly — S4 Task 3 regression gate.
// Per ADR-0042, components with `pkg:golang/...` PURLs MUST surface
// their resolver-derived CPE in `astinus:cpe:evidence` rather than
// in `c.CPE` (the scanner-facing field), and the version slot must
// have the leading `v` stripped (NVD stores `:1.9.3:`, not
// `:v1.9.3:`).
func TestS4T3_GolangCPEsLandAsEvidenceOnly(t *testing.T) {
	logrusPURL := "pkg:golang/github.com/sirupsen/logrus@v1.9.3"
	inputSBOM := s4.WriteCDXSBOM(t,
		[]cdx.Component{{
			BOMRef:     "comp-logrus",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "github.com/sirupsen/logrus",
			Version:    "v1.9.3",
			PackageURL: logrusPURL,
		}},
		cdx.Tool{Name: "syft"},
	)

	res := s3.RunEnrichOK(t, s3.EnrichOpts{
		SBOM:      inputSBOM,
		Image:     "test/empty:1", // helper materialises a minimal OCI image
		NoNetwork: true,
	})
	if res.BOM == nil {
		t.Fatal("no BOM in output")
	}

	logrus := s4.FindComponent(res.BOM, "github.com/sirupsen/logrus", "")
	if logrus == nil {
		t.Fatalf("logrus component missing from output; %d components total",
			len(*res.BOM.Components))
	}
	if logrus.CPE != "" {
		t.Errorf("primary CPE leaked on golang component: %q (must be evidence-only)", logrus.CPE)
	}
	ev := s4.PropertyValue(logrus, "astinus:cpe:evidence")
	if ev == "" || !strings.HasPrefix(ev, "cpe:2.3:") {
		t.Errorf("astinus:cpe:evidence = %q, want a CPE 2.3 URI", ev)
	}
	if scope := s4.PropertyValue(logrus, "astinus:cpe:scope"); scope != "evidence-only" {
		t.Errorf("astinus:cpe:scope = %q, want evidence-only", scope)
	}
	if rationale := s4.PropertyValue(logrus, "astinus:cpe:rationale"); rationale == "" {
		t.Errorf("astinus:cpe:rationale missing on evidence-only row")
	}
	if strings.Contains(ev, ":v1.9.3:") {
		t.Errorf("v-prefix leaked in evidence CPE: %q", ev)
	}
}
