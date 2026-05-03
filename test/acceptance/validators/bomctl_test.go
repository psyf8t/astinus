//go:build acceptance

package validators

import (
	"path/filepath"
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/helpers"
)

func TestAcceptance_BomctlQuality(t *testing.T) {
	helpers.RequireDockerDaemon(t)
	helpers.RequireCommand(t, "bomctl")

	img := helpers.BuildImage(t, validatorSimpleDockerfile, nil)
	syft := helpers.GenSyftSBOM(t, img)
	bom := helpers.RunAstinusFull(t, helpers.AstinusOpts{SBOM: syft, Image: img})

	out := filepath.Join(t.TempDir(), "astinus.cdx.json")
	helpers.SaveJSON(t, out, bom)

	// `bomctl validate` reports schema + completeness issues.
	// We treat any non-zero exit as a failure so an operator
	// landing here knows quality regressed.
	helpers.RunOK(t, "bomctl", "validate", out)
}
