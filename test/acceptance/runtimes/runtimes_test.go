//go:build acceptance

package runtimes

import (
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/helpers"
)

// TestAcceptance_FiveRuntimes asserts the Track C contract — five
// builders all produce SBOMs that:
//
//   - report a runtime matching the builder name,
//   - have zero duplicates,
//   - pass NTIA at the critical-floor.
//
// Each row uses the same dockerfile so any difference is purely
// from the builder, not the workload.
func TestAcceptance_FiveRuntimes(t *testing.T) {
	cases := []struct {
		name  string
		build func(helpers.TB, string) string
	}{
		{"docker", helpers.BuildWithDocker},
		{"buildkit", helpers.BuildWithBuildKit},
		{"podman", helpers.BuildWithPodman},
		{"buildah", helpers.BuildWithBuildah},
		{"kaniko", helpers.BuildWithKaniko},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			img := tc.build(t, helpers.SimpleDockerfile)
			syft := helpers.GenSyftSBOM(t, img)
			bom := helpers.RunAstinusFull(t, helpers.AstinusOpts{SBOM: syft, Image: img})

			if got := helpers.GetRuntimeProperty(bom); got != tc.name {
				t.Errorf("runtime = %q, want %q", got, tc.name)
			}
			if dups := helpers.CountDuplicates(bom); dups != 0 {
				t.Errorf("duplicates = %d, want 0", dups)
			}
			ntia := helpers.GetNTIAFindings(bom)
			if got := len(helpers.FilterBySeverity(ntia, "critical")); got != 0 {
				t.Errorf("NTIA critical findings = %d, want 0", got)
			}
		})
	}
}
