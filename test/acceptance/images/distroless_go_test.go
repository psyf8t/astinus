//go:build acceptance

package images

import (
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/helpers"
)

const distrolessGoDockerfile = `FROM golang:1.22 AS builder
RUN mkdir -p /tmp/proj && \
    printf 'package main\nimport "fmt"\nfunc main() { fmt.Println("hi") }\n' > /tmp/proj/main.go && \
    cd /tmp/proj && go mod init demo && CGO_ENABLED=0 go build -o /app .

FROM gcr.io/distroless/static-debian12
COPY --from=builder /app /app
CMD ["/app"]
`

func TestAcceptance_DistrolessGo(t *testing.T) {
	helpers.RequireDockerDaemon(t)
	img := helpers.BuildImage(t, distrolessGoDockerfile, nil)
	syft := helpers.GenSyftSBOM(t, img)
	bom := helpers.RunAstinusFull(t, helpers.AstinusOpts{SBOM: syft, Image: img})

	// Distroless has very little metadata; everything must be either
	// base or app, so origin coverage should be high.
	if cov := helpers.ComputeOriginCoverage(bom); cov < 0.9 {
		t.Errorf("origin coverage = %.2f, want ≥ 0.90 (distroless)", cov)
	}

	// The Go binary at /app must be detected with a PURL extracted
	// from its embedded buildinfo.
	bin := helpers.FindComponentByPath(bom, "/app")
	if bin == nil {
		t.Fatal("Go binary at /app must be detected")
	}
	if bin.PackageURL == "" {
		t.Error("Go binary must carry a PURL (extracted from buildinfo)")
	}

	// Distroless built with a normal docker daemon should NOT be
	// flagged as low confidence — that's reserved for kaniko/squash.
	if conf := helpers.GetAttributionConfidence(bom); conf == "low" {
		t.Errorf("attribution confidence = %q; distroless+docker should not be low", conf)
	}
}
