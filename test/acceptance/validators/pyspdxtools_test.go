//go:build acceptance

package validators

import (
	"path/filepath"
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/helpers"
)

func TestAcceptance_PySPDXTools(t *testing.T) {
	helpers.RequireDockerDaemon(t)
	// pyspdxtools ships its CLI as `pyspdxtools` after pip install.
	helpers.RequireCommand(t, "pyspdxtools")

	img := helpers.BuildImage(t, validatorSimpleDockerfile, nil)
	syft := helpers.GenSyftSBOM(t, img)

	// Render astinus's SPDX-JSON output (rather than CycloneDX) so
	// pyspdxtools has something to validate.
	bin := filepath.Join(t.TempDir(), "astinus-bin")
	helpers.RunOK(t, "go", "build", "-o", bin, helpers.RepoCmdAstinus(t))
	out := filepath.Join(t.TempDir(), "astinus.spdx.json")
	helpers.RunOK(t, bin,
		"enrich",
		"--sbom", syft,
		"--image", img,
		"--output", out,
		"--output-format", "spdx-json",
	)
	helpers.RunOK(t, "pyspdxtools", "-i", out, "--novalidation=false")
}
