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

// largeNpmSBOM generates a CycloneDX SBOM with n npm components.
// Used by the cpe-mode tests to push past the
// `nvdHybridSkipThreshold = 50` predicate so the auto-mode skip
// (or hybrid fail-fast) actually fires.
func largeNpmSBOM(tb testing.TB, n int) string {
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

// TestS4T4_AutoModeSkipsNVDAndStampsMetadata — S4 Task 4 regression
// gate. The default `--cpe-mode auto` MUST gracefully skip the NVD
// online source when no API key is set + workload exceeds the rate
// threshold, stamp the SBOM-level
// `astinus:cpe:sources-skipped = online-nvd` property, and exit 0.
// ADR-0043.
func TestS4T4_AutoModeSkipsNVDAndStampsMetadata(t *testing.T) {
	sbom := largeNpmSBOM(t, 60) // above the 50-component threshold

	res := s3.RunEnrichOK(t, s3.EnrichOpts{
		SBOM:  sbom,
		Image: "test/empty:1",
		Extra: []string{"--cpe-mode", "auto"},
		// Deliberately no NVD_API_KEY in opts.Env; the helper passes
		// the inherited environment through, and CI / dev shells
		// generally don't carry the var.
	})
	if res.BOM == nil {
		t.Fatal("no BOM in output")
	}
	if got := s4.MetadataProperty(res.BOM, "astinus:cpe:mode"); got != "auto" {
		t.Errorf("astinus:cpe:mode = %q, want auto", got)
	}
	skipped := s4.MetadataProperty(res.BOM, "astinus:cpe:sources-skipped")
	if !strings.Contains(skipped, "online-nvd") {
		t.Errorf("astinus:cpe:sources-skipped = %q, want to include online-nvd", skipped)
	}
}

// TestS4T4_HybridModeExits60WithoutAPIKey — S4 Task 4 strict-mode
// gate. `--cpe-mode hybrid` (or the deprecated `online` alias) MUST
// fail fast with exit `ExitCPESourceUnavailable = 60` when an
// expected online source is unavailable. The error message MUST
// list the actionable resolutions. ADR-0043.
func TestS4T4_HybridModeExits60WithoutAPIKey(t *testing.T) {
	sbom := largeNpmSBOM(t, 60)

	res := s3.RunEnrich(t, s3.EnrichOpts{
		SBOM:  sbom,
		Image: "test/empty:1",
		Extra: []string{"--cpe-mode", "hybrid"},
		// Force no API key — env-override via opts.Env replaces the
		// inherited env entirely. Pass the PATH / HOME the binary
		// needs to run go build but omit NVD_API_KEY.
		Env: minimalEnv(t),
	})
	if res.ExitCode != 60 {
		t.Fatalf("exit code = %d, want 60 (ExitCPESourceUnavailable)\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}
	for _, want := range []string{
		"NVD_API_KEY",
		"--cpe-mode=auto",
		"--cpe-mode=offline",
	} {
		if !strings.Contains(res.Stderr, want) {
			t.Errorf("stderr missing actionable hint %q\nfull stderr:\n%s", want, res.Stderr)
		}
	}
}

// TestS4T4_OnlineAliasDeprecationWarnsAndBehavesAsHybrid — S4 Task 4
// keeps the pre-S4 `--cpe-mode online` accepted for backwards-
// compatibility (planned removal in v1.0.0) but logs a deprecation
// warning and exits with the same strict behaviour.
func TestS4T4_OnlineAliasDeprecationWarnsAndBehavesAsHybrid(t *testing.T) {
	sbom := largeNpmSBOM(t, 60)

	res := s3.RunEnrich(t, s3.EnrichOpts{
		SBOM:  sbom,
		Image: "test/empty:1",
		Extra: []string{"--cpe-mode", "online"},
		Env:   minimalEnv(t),
	})
	if res.ExitCode != 60 {
		t.Errorf("online-alias exit code = %d, want 60\nstderr:\n%s", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stderr, "cpe.mode.deprecated") &&
		!strings.Contains(res.Stdout, "cpe.mode.deprecated") {
		t.Errorf("expected cpe.mode.deprecated log line\nstdout:\n%s\nstderr:\n%s",
			res.Stdout, res.Stderr)
	}
}
