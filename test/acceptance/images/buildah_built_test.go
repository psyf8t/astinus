//go:build acceptance

package images

import (
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/helpers"
)

const buildahSimpleDockerfile = `FROM alpine:3.19
RUN apk add --no-cache curl
RUN echo "buildah-test" > /etc/build-marker
`

func TestAcceptance_BuildahBuilt(t *testing.T) {
	if !helpers.CanRunBuildah() {
		t.Skip("buildah not available")
	}
	img := helpers.BuildWithBuildah(t, buildahSimpleDockerfile)
	syft := helpers.GenSyftSBOM(t, img)
	bom := helpers.RunAstinusFull(t, helpers.AstinusOpts{SBOM: syft, Image: img})

	// Runtime detection: buildah produces native OCI bundles. The
	// runtime detector should identify the source as buildah (not
	// docker / buildkit).
	if rt := helpers.GetRuntimeProperty(bom); rt != "buildah" {
		t.Errorf("runtime = %q, want \"buildah\"", rt)
	}

	// 0 critical NTIA findings — buildah's metadata is rich enough
	// to satisfy the floor.
	ntia := helpers.GetNTIAFindings(bom)
	if got := len(helpers.FilterBySeverity(ntia, "critical")); got != 0 {
		t.Errorf("NTIA critical findings = %d, want 0", got)
	}

	if dups := helpers.CountDuplicates(bom); dups != 0 {
		t.Errorf("duplicates = %d, want 0", dups)
	}
}
