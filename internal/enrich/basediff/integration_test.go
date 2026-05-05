//go:build integration

package basediff_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"

	"github.com/psyf8t/astinus/internal/enrich/basediff"
	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestContentStrategyMultiStage builds a multi-stage image with
// real `docker build` and asserts that the content-addressable
// strategy correctly classifies a component whose file was copied
// across stages.
//
// This is the case the legacy layer-prefix / path-fallback diff
// cannot solve: the target image's first layer does NOT match the
// base's layer digest (multi-stage breaks the prefix), and the
// component's path in the target differs from where it lived in
// the base (`COPY --from=builder /usr/bin/curl /usr/local/bin/`).
func TestContentStrategyMultiStage(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	dir := writeMultiStageContext(t)

	baseTag := "astinus-bd-base:test"
	targetTag := "astinus-bd-target:test"
	defer dockerRmi(baseTag, targetTag)

	if out, err := exec.Command("docker", "build", "-f", filepath.Join(dir, "Dockerfile.base"),
		"-t", baseTag, dir).CombinedOutput(); err != nil {
		t.Fatalf("docker build base: %v\n%s", err, out)
	}
	if out, err := exec.Command("docker", "build", "-f", filepath.Join(dir, "Dockerfile.target"),
		"--build-arg", "BASE_TAG="+baseTag,
		"-t", targetTag, dir).CombinedOutput(); err != nil {
		t.Fatalf("docker build target: %v\n%s", err, out)
	}

	baseImg := loadFromDaemon(t, baseTag)
	targetImg := loadFromDaemon(t, targetTag)

	// Synthesise an SBOM that names the file the multi-stage flow
	// copied. In production Syft would supply this; here we
	// fabricate it so the test exercises the basediff path
	// independently of Syft's quirks.
	sbom := &model.SBOM{
		Components: []model.Component{{
			Name: "copied-fixture",
			Evidence: &model.Evidence{
				Locations: []model.EvidenceLocation{{Path: "usr/local/bin/fixture.txt"}},
			},
		}},
	}

	bundle := image.NewBundle(mustTag(t, targetTag), targetImg, sbom)
	baseBundle := image.NewBundle(mustTag(t, baseTag), baseImg, sbom)

	// Run the content strategy directly via a hand-built Enricher
	// (so the test does not require image.Open, which would fight
	// the test daemon).
	e := basediff.NewWithOptions(basediff.Options{Mode: basediff.ModeNone})
	_ = e // Mode=None actually short-circuits; use the ExposedRunContentStrategy below.

	if !basediff.RunContentStrategyForTest(context.Background(), sbom, bundle, baseBundle, "test/base") {
		t.Fatal("RunContentStrategyForTest returned false")
	}

	if sbom.Components[0].Origin != model.OriginBaseImage {
		t.Errorf("Origin = %q, want base (multi-stage copy must be classified as base)",
			sbom.Components[0].Origin)
	}
	if sbom.Components[0].Properties[model.PropertyBasediffMatchedBasePath] == "" {
		t.Error("matched-base-path was not stamped")
	}
}

// writeMultiStageContext writes a tiny self-contained build context
// with a fixture file plus two Dockerfiles: one for the base image
// and one for the target image. The target uses the base in a
// multi-stage build and copies the fixture file under a different
// path — the case the content strategy is supposed to win on.
func writeMultiStageContext(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fixture.txt"),
		[]byte("astinus-multistage-fixture-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile.base"),
		[]byte("FROM scratch\nCOPY fixture.txt /usr/bin/fixture.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile.target"), []byte(`
ARG BASE_TAG
FROM ${BASE_TAG} AS builder
FROM scratch
COPY --from=builder /usr/bin/fixture.txt /usr/local/bin/fixture.txt
`), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func dockerRmi(tags ...string) {
	for _, t := range tags {
		_ = exec.Command("docker", "rmi", t).Run()
	}
}

func loadFromDaemon(t *testing.T, tag string) v1.Image {
	t.Helper()
	ref, err := name.ParseReference(tag)
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	img, err := daemon.Image(ref, daemon.WithContext(context.Background()))
	if err != nil {
		t.Fatalf("daemon.Image %q: %v", tag, err)
	}
	return img
}

func mustTag(t *testing.T, ref string) name.Tag {
	t.Helper()
	tag, err := name.NewTag(strings.TrimSpace(ref))
	if err != nil {
		t.Fatalf("parse tag: %v", err)
	}
	return tag
}

// silence unused-fmt imports when the build tag isn't active.
var _ = fmt.Sprintf
