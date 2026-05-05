//go:build acceptance

package images

import (
	"strings"
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/helpers"
)

const kanikoSimpleDockerfile = `FROM alpine:3.19
RUN apk add --no-cache curl
RUN echo "hello" > /etc/hello.txt
`

func TestAcceptance_KanikoBuilt(t *testing.T) {
	helpers.RequireDockerDaemon(t) // needs docker to load the kaniko tar
	if !helpers.CanRunKaniko() {
		t.Skip("kaniko (executor binary) not available — install via gcr.io/kaniko-project/executor")
	}

	img := helpers.BuildWithKaniko(t, kanikoSimpleDockerfile)
	syft := helpers.GenSyftSBOM(t, img)
	bom := helpers.RunAstinusFull(t, helpers.AstinusOpts{SBOM: syft, Image: img})

	// Runtime detection: kaniko's flatten produces images without
	// docker/buildkit metadata; the runtime detector should call it.
	if rt := helpers.GetRuntimeProperty(bom); rt != "kaniko" {
		t.Errorf("runtime = %q, want \"kaniko\"", rt)
	}

	// Squashed-layer detection: confidence should be marked low.
	if conf := helpers.GetAttributionConfidence(bom); conf != "low" {
		t.Errorf("attribution confidence = %q, want \"low\" (kaniko/squash)", conf)
	}

	// Reason must explain why.
	if reason := helpers.GetAttributionReason(bom); !strings.Contains(strings.ToLower(reason), "squash") {
		t.Errorf("attribution reason = %q, want it to mention 'squash'", reason)
	}
}
