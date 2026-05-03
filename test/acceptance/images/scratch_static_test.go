//go:build acceptance

package images

import (
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/helpers"
)

const scratchStaticDockerfile = `FROM golang:1.22 AS builder
RUN mkdir -p /tmp/proj && \
    printf 'package main\nimport "fmt"\nfunc main() { fmt.Println("scratch") }\n' > /tmp/proj/main.go && \
    cd /tmp/proj && go mod init scratchdemo && CGO_ENABLED=0 go build -o /app .

FROM scratch
COPY --from=builder /app /app
ENTRYPOINT ["/app"]
`

func TestAcceptance_ScratchStatic(t *testing.T) {
	helpers.RequireDockerDaemon(t)
	img := helpers.BuildImage(t, scratchStaticDockerfile, nil)
	syft := helpers.GenSyftSBOM(t, img)
	bom := helpers.RunAstinusFull(t, helpers.AstinusOpts{SBOM: syft, Image: img})

	// Scratch is the empty-base case: every component must be the
	// app binary or its embedded modules. Component count is tiny.
	if got := helpers.ComponentCount(bom); got >= 100 {
		t.Errorf("component count = %d, scratch image should have <100", got)
	}

	// The app must show up.
	bin := helpers.FindComponentByPath(bom, "/app")
	if bin == nil {
		t.Fatal("scratch image must still surface the /app Go binary")
	}

	// Origin coverage = 100% expected (every component is either
	// the binary itself or a module embedded in it).
	if cov := helpers.ComputeOriginCoverage(bom); cov < 0.95 {
		t.Errorf("origin coverage = %.2f, want ≥ 0.95 (scratch)", cov)
	}

	// 0 dups.
	if dups := helpers.CountDuplicates(bom); dups != 0 {
		t.Errorf("duplicates = %d, want 0", dups)
	}
}
