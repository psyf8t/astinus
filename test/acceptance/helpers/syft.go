package helpers

import (
	"path/filepath"
)

// GenSyftSBOM runs `syft <imageRef> -o cyclonedx-json=<path>` and
// returns the file path of the generated SBOM. Skips the test when
// syft is not installed.
//
// The SBOM lives under t.TempDir(); it is removed automatically.
func GenSyftSBOM(t TB, imageRef string) string {
	t.Helper()
	RequireCommand(t, "syft")
	out := filepath.Join(t.TempDir(), "syft.cdx.json")
	// `syft` accepts both `docker:` and image-reference shorthands;
	// pass the bare ref and let syft pick the right backend.
	RunOK(t, "syft", imageRef, "-o", "cyclonedx-json="+out, "-q")
	return out
}

// GenSyftSBOMFromArchive runs syft against an exported docker tar.
// Useful when the test built the image with one runtime and wants
// syft to read the OCI layout without going through any daemon.
func GenSyftSBOMFromArchive(t TB, tarPath string) string {
	t.Helper()
	RequireCommand(t, "syft")
	out := filepath.Join(t.TempDir(), "syft.cdx.json")
	RunOK(t, "syft", "docker-archive:"+tarPath, "-o", "cyclonedx-json="+out, "-q")
	return out
}
