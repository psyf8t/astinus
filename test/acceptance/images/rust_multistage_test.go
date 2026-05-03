//go:build acceptance

package images

import (
	"strings"
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/helpers"
)

const rustMultistageDockerfile = `FROM rust:1.75 AS builder
WORKDIR /build
RUN cargo init --name demo
RUN cargo add serde@1.0 --features derive
RUN cargo build --release

FROM alpine:3.19
RUN apk add --no-cache libgcc
COPY --from=builder /build/target/release/demo /usr/local/bin/demo
CMD ["/usr/local/bin/demo"]
`

func TestAcceptance_RustMultistage(t *testing.T) {
	helpers.RequireDockerDaemon(t)
	img := helpers.BuildImage(t, rustMultistageDockerfile, nil)
	syft := helpers.GenSyftSBOM(t, img)
	bom := helpers.RunAstinusFull(t, helpers.AstinusOpts{SBOM: syft, Image: img})

	// Rust extractor: at least one pkg:cargo/* PURL must come out
	// of the binary's embedded .dep-v0 audit data.
	if !helpers.AnyPURLMatches(bom, func(p string) bool {
		return strings.HasPrefix(p, "pkg:cargo/")
	}) {
		t.Error("expected at least one pkg:cargo/* PURL — Rust extractor missed audit data")
	}

	// The demo binary must be detected.
	if !helpers.HasComponent(bom, "demo") && helpers.FindComponentByPath(bom, "/usr/local/bin/demo") == nil {
		t.Error("Rust /usr/local/bin/demo binary must be detected")
	}

	// Origin coverage ≥ 90% (multi-stage with explicit COPY pattern).
	if cov := helpers.ComputeOriginCoverage(bom); cov < 0.9 {
		t.Errorf("origin coverage = %.2f, want ≥ 0.90", cov)
	}

	if dups := helpers.CountDuplicates(bom); dups != 0 {
		t.Errorf("duplicates = %d, want 0", dups)
	}
}
