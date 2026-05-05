//go:build acceptance

package images

import (
	"strings"
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/helpers"
)

const multistageNodeDockerfile = `FROM node:20-bullseye AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends wget && rm -rf /var/lib/apt/lists/*
RUN wget -q https://github.com/mikefarah/yq/releases/download/v4.40.5/yq_linux_amd64 -O /opt/yq && chmod +x /opt/yq
RUN echo '{"name":"test","version":"1.0.0","dependencies":{"lodash":"4.17.20"}}' > package.json
RUN npm install

FROM node:20-slim
COPY --from=builder /opt/yq /usr/local/bin/yq
COPY --from=builder /build/node_modules /app/node_modules
WORKDIR /app
CMD ["node", "-e", "console.log('ok')"]
`

func TestAcceptance_MultistageNode(t *testing.T) {
	helpers.RequireDockerDaemon(t)
	img := helpers.BuildImage(t, multistageNodeDockerfile, nil)
	syft := helpers.GenSyftSBOM(t, img)
	bom := helpers.RunAstinusFull(t, helpers.AstinusOpts{
		SBOM:  syft,
		Image: img,
		Mode:  "hybrid",
	})

	// Track A: Compliance — 0 critical, ≤5 high NTIA findings.
	ntia := helpers.GetNTIAFindings(bom)
	if got := len(helpers.FilterBySeverity(ntia, "critical")); got != 0 {
		t.Errorf("NTIA critical findings = %d, want 0", got)
	}
	if got := len(helpers.FilterBySeverity(ntia, "high")); got > 5 {
		t.Errorf("NTIA high findings = %d, want ≤5", got)
	}

	// Track B: Vuln scanning — CPE ≥ 60% (hybrid), PURL ≥ 70%.
	if cov := helpers.ComputeCPECoverage(bom); cov < 0.6 {
		t.Errorf("CPE coverage = %.2f, want ≥ 0.60 (hybrid)", cov)
	}
	if cov := helpers.ComputePURLCoverage(bom); cov < 0.7 {
		t.Errorf("PURL coverage = %.2f, want ≥ 0.70", cov)
	}

	// Track C: Attribution — origin ≥ 90%, runtime detected as docker.
	if cov := helpers.ComputeOriginCoverage(bom); cov < 0.9 {
		t.Errorf("origin coverage = %.2f, want ≥ 0.90", cov)
	}
	if runtime := helpers.GetRuntimeProperty(bom); runtime != "docker" {
		t.Errorf("runtime = %q, want \"docker\" (classic builder)", runtime)
	}

	// General quality: 0 dups, < 5000 components.
	if dups := helpers.CountDuplicates(bom); dups != 0 {
		t.Errorf("duplicates = %d, want 0", dups)
	}
	if got := helpers.ComponentCount(bom); got >= 5000 {
		t.Errorf("component count = %d, want < 5000", got)
	}

	// Specific finding: yq detected with a Go PURL (extracted from buildinfo).
	yq := helpers.FindComponent(bom, "yq")
	if yq == nil {
		t.Fatal("yq from /opt/yq must be detected")
	}
	if yq.Version == "" {
		t.Error("yq version must be extracted")
	}
	if !strings.Contains(yq.PackageURL, "pkg:golang/") {
		t.Errorf("yq PURL = %q, want pkg:golang/* (buildinfo extractor)", yq.PackageURL)
	}
}
