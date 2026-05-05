//go:build acceptance

package helpers

import (
	"os"
	"path/filepath"
	"testing"
)

// MinimalNpmSBOM returns a CycloneDX-1.6 SBOM with two npm
// components (lodash + express). The Sprint 3 registry / lifecycle
// acceptance tests use this as the input — the components have PURLs
// the registry resolver routes to npm, so the FakeNpmMirror gets
// asked for them.
//
// No CPEs, no licenses, no descriptions: the point of these tests is
// that the registry enricher fills those in.
const MinimalNpmSBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
  "version": 1,
  "metadata": {
    "timestamp": "2026-05-04T00:00:00Z",
    "component": {
      "bom-ref": "test-image",
      "type": "container",
      "name": "test-image",
      "version": "1.0"
    }
  },
  "components": [
    {
      "bom-ref": "pkg:npm/lodash@4.17.20",
      "type": "library",
      "name": "lodash",
      "version": "4.17.20",
      "purl": "pkg:npm/lodash@4.17.20"
    },
    {
      "bom-ref": "pkg:npm/express@4.17.0",
      "type": "library",
      "name": "express",
      "version": "4.17.0",
      "purl": "pkg:npm/express@4.17.0"
    }
  ]
}`

// MinimalRuntimeSBOM has OS + runtime components useful for the
// lifecycle / EOL test path: nodejs (LTS, supported), python 3.8
// (EOL since 2024-10-01), debian 10 (EOL since 2024-06-30). The
// lifecycle enricher tags each with the appropriate state property.
const MinimalRuntimeSBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
  "version": 1,
  "metadata": {
    "timestamp": "2026-05-04T00:00:00Z",
    "component": {
      "bom-ref": "test-image",
      "type": "container",
      "name": "test-image",
      "version": "1.0"
    }
  },
  "components": [
    {
      "bom-ref": "comp:nodejs",
      "type": "application",
      "name": "node",
      "version": "20.18.0",
      "purl": "pkg:generic/nodejs@20.18.0",
      "cpe": "cpe:2.3:a:nodejs:node.js:20.18.0:*:*:*:*:*:*:*"
    },
    {
      "bom-ref": "comp:python",
      "type": "application",
      "name": "python",
      "version": "3.8.20",
      "purl": "pkg:generic/python@3.8.20",
      "cpe": "cpe:2.3:a:python:python:3.8.20:*:*:*:*:*:*:*"
    },
    {
      "bom-ref": "comp:debian",
      "type": "operating-system",
      "name": "debian",
      "version": "10",
      "purl": "pkg:generic/debian@10",
      "cpe": "cpe:2.3:o:debian:debian_linux:10:*:*:*:*:*:*:*"
    }
  ]
}`

// WriteSBOMFixture drops body to dir/name and returns the absolute
// path. Tests pass that path as `--sbom` to the astinus binary.
func WriteSBOMFixture(tb testing.TB, dir, name, body string) string {
	tb.Helper()
	if dir == "" {
		dir = tb.TempDir()
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		tb.Fatalf("write fixture %s: %v", path, err)
	}
	return path
}
