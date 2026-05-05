//go:build acceptance

package images

import (
	"strings"
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/helpers"
)

const pythonPoetryDockerfile = `FROM python:3.11-slim AS builder
WORKDIR /build
RUN pip install --no-cache-dir poetry==1.8.3
COPY pyproject.toml poetry.lock* ./
RUN poetry install --no-root --only main && \
    poetry export -f requirements.txt -o /tmp/req.txt --without-hashes
RUN pip install --no-cache-dir --target=/install -r /tmp/req.txt

FROM python:3.11-slim
COPY --from=builder /install /usr/local/lib/python3.11/site-packages
WORKDIR /app
CMD ["python", "-c", "import requests; print(requests.__version__)"]
`

const pythonPyproject = `[tool.poetry]
name = "demo"
version = "0.1.0"
description = ""
authors = ["test"]

[tool.poetry.dependencies]
python = "^3.11"
requests = "2.31.0"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
`

func TestAcceptance_PythonPoetry(t *testing.T) {
	helpers.RequireDockerDaemon(t)
	img := helpers.BuildImage(t, pythonPoetryDockerfile, map[string][]byte{
		"pyproject.toml": []byte(pythonPyproject),
	})
	syft := helpers.GenSyftSBOM(t, img)
	bom := helpers.RunAstinusFull(t, helpers.AstinusOpts{SBOM: syft, Image: img})

	// Python ecosystem: at least one pkg:pypi/* PURL.
	if !helpers.AnyPURLMatches(bom, func(p string) bool {
		return strings.HasPrefix(p, "pkg:pypi/")
	}) {
		t.Error("expected at least one pkg:pypi/* PURL")
	}

	// requests must be detected by name.
	if !helpers.HasComponent(bom, "requests") {
		t.Error("requests must be detected as a component")
	}

	// Origin coverage ≥ 90%.
	if cov := helpers.ComputeOriginCoverage(bom); cov < 0.9 {
		t.Errorf("origin coverage = %.2f, want ≥ 0.90", cov)
	}

	if dups := helpers.CountDuplicates(bom); dups != 0 {
		t.Errorf("duplicates = %d, want 0", dups)
	}
}
