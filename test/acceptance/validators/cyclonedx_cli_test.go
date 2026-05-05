//go:build acceptance

package validators

import (
	"path/filepath"
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/helpers"
)

const validatorSimpleDockerfile = `FROM alpine:3.19
RUN apk add --no-cache curl
`

func TestAcceptance_CycloneDXCLI(t *testing.T) {
	helpers.RequireDockerDaemon(t)
	helpers.RequireCommand(t, "cyclonedx")

	img := helpers.BuildImage(t, validatorSimpleDockerfile, nil)
	syft := helpers.GenSyftSBOM(t, img)
	bom := helpers.RunAstinusFull(t, helpers.AstinusOpts{SBOM: syft, Image: img})

	// Persist the BOM and let cyclonedx-cli validate it.
	out := filepath.Join(t.TempDir(), "astinus.cdx.json")
	helpers.SaveJSON(t, out, bom)

	helpers.RunOK(t, "cyclonedx", "validate", "--input-file", out)
}
