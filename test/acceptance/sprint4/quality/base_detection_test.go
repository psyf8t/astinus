//go:build acceptance

package quality

import (
	"strings"
	"testing"

	s3 "github.com/psyf8t/astinus/test/acceptance/sprint3/helpers"
	s4 "github.com/psyf8t/astinus/test/acceptance/sprint4/helpers"
)

// TestS4T6_ContentBaseDetectionFromOSRelease — S4 Task 6 regression
// gate. `--base auto` (the default) MUST fall back to content-based
// detection when the target image carries no
// `org.opencontainers.image.base.*` labels: read /etc/os-release,
// match against the bundled known-bases catalogue, stamp the
// outcome on SBOM metadata. ADR-0045.
func TestS4T6_ContentBaseDetectionFromOSRelease(t *testing.T) {
	image := s4.OCIImageWithFiles(t, map[string][]byte{
		"etc/os-release": []byte(`ID=alpine
VERSION_ID=3.20.6
PRETTY_NAME="Alpine Linux v3.20"
`),
		// Three of the catalogue's sample_file_paths for alpine 3.20;
		// presence pushes the score past the 0.70 default threshold.
		"etc/alpine-release":   []byte("3.20.6\n"),
		"etc/apk/repositories": []byte("https://dl-cdn.alpinelinux.org/alpine/v3.20/main\n"),
		"lib/apk/db/installed": []byte("P:musl\nV:1.2.5\n"),
	})
	emptySBOM := s4.WriteCDXSBOM(t, nil)

	res := s3.RunEnrichOK(t, s3.EnrichOpts{
		SBOM:      emptySBOM,
		Image:     image,
		NoNetwork: true,
	})
	if res.BOM == nil {
		t.Fatal("no BOM in output")
	}
	if got := s4.MetadataProperty(res.BOM, "astinus:basediff:detection-method"); got != "os-release+known-bases" {
		t.Errorf("detection-method = %q, want os-release+known-bases", got)
	}
	if got := s4.MetadataProperty(res.BOM, "astinus:basediff:detected-base"); got != "alpine:3.20" {
		t.Errorf("detected-base = %q, want alpine:3.20", got)
	}
	if got := s4.MetadataProperty(res.BOM, "astinus:basediff:os-release-id"); got != "alpine" {
		t.Errorf("os-release-id = %q, want alpine", got)
	}
}

// TestS4T6_ScratchImageStampsFallbackReason — when the target is
// scratch-based (or some custom image with no os-release file),
// detection MUST surface an explicit fallback-reason on
// sbom.Metadata.Properties so operators see why no base was
// identified.
func TestS4T6_ScratchImageStampsFallbackReason(t *testing.T) {
	image := s4.OCIImageWithFiles(t, map[string][]byte{
		"usr/local/bin/app": []byte("opaque binary blob"),
	})
	emptySBOM := s4.WriteCDXSBOM(t, nil)

	res := s3.RunEnrichOK(t, s3.EnrichOpts{
		SBOM:      emptySBOM,
		Image:     image,
		NoNetwork: true,
	})
	if res.BOM == nil {
		t.Fatal("no BOM in output")
	}
	if got := s4.MetadataProperty(res.BOM, "astinus:basediff:detected-base"); got != "" {
		t.Errorf("detected-base = %q, want empty on scratch", got)
	}
	reason := s4.MetadataProperty(res.BOM, "astinus:basediff:detection-fallback-reason")
	if !strings.Contains(reason, "os-release") {
		t.Errorf("detection-fallback-reason = %q, want mention of os-release", reason)
	}
}
