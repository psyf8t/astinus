package runtime

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// ─── Helpers ──────────────────────────────────────────────────────────────

// imageWithConfig returns an image whose ConfigFile is the supplied
// value (with sensible RootFS defaults so go-containerregistry's
// internal validation does not reject it).
func imageWithConfig(t *testing.T, cf v1.ConfigFile) v1.Image {
	t.Helper()
	if cf.OS == "" {
		cf.OS = "linux"
	}
	if cf.Architecture == "" {
		cf.Architecture = "amd64"
	}
	if cf.RootFS.Type == "" {
		cf.RootFS.Type = "layers"
	}
	img, err := mutate.ConfigFile(empty.Image, &cf)
	if err != nil {
		t.Fatalf("mutate.ConfigFile: %v", err)
	}
	return img
}

// imageWithLayersAndConfig appends nLayers minimal tar layers to
// empty.Image then merges cf into the resulting image's config
// (preserving the RootFS diff IDs that AppendLayers populated — a
// raw mutate.ConfigFile would clobber them and leave img.Layers()
// returning zero).
func imageWithLayersAndConfig(t *testing.T, nLayers int, cf v1.ConfigFile) v1.Image {
	t.Helper()
	img := empty.Image
	for i := 0; i < nLayers; i++ {
		layer := makeTinyLayer(t, i)
		var err error
		img, err = mutate.AppendLayers(img, layer)
		if err != nil {
			t.Fatalf("AppendLayers: %v", err)
		}
	}
	existing, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("ConfigFile: %v", err)
	}
	merged := *existing
	merged.Author = cf.Author
	merged.History = cf.History
	if cf.Config.Labels != nil {
		merged.Config.Labels = cf.Config.Labels
	}
	if len(cf.Config.Entrypoint) > 0 {
		merged.Config.Entrypoint = cf.Config.Entrypoint
	}
	out, err := mutate.ConfigFile(img, &merged)
	if err != nil {
		t.Fatalf("mutate.ConfigFile: %v", err)
	}
	return out
}

func makeTinyLayer(t *testing.T, idx int) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte{byte(idx)}
	if err := tw.WriteHeader(&tar.Header{
		Name: "f", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	bs := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bs)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return layer
}

// ─── Detect ───────────────────────────────────────────────────────────────

func TestDetectNilImage(t *testing.T) {
	rt, ev, err := Detect(nil)
	if err == nil {
		t.Fatal("expected error for nil image")
	}
	if rt != RuntimeUnknown {
		t.Errorf("rt = %q, want %q", rt, RuntimeUnknown)
	}
	if ev != nil {
		t.Errorf("ev = %v, want nil", ev)
	}
}

func TestDetectDefaultsToDocker(t *testing.T) {
	img := imageWithConfig(t, v1.ConfigFile{})
	rt, ev, err := Detect(img)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt != RuntimeDocker {
		t.Errorf("rt = %q, want %q", rt, RuntimeDocker)
	}
	if ev != nil {
		t.Errorf("ev = %v, want nil for default fallback", ev)
	}
}

func TestDetectKanikoByAuthor(t *testing.T) {
	img := imageWithConfig(t, v1.ConfigFile{Author: "Kaniko"})
	rt, ev, err := Detect(img)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt != RuntimeKaniko {
		t.Errorf("rt = %q, want %q", rt, RuntimeKaniko)
	}
	if len(ev) != 1 || ev[0].Field != "config.Author" {
		t.Errorf("evidence = %+v, want config.Author", ev)
	}
}

func TestDetectKanikoByLabel(t *testing.T) {
	img := imageWithConfig(t, v1.ConfigFile{
		Config: v1.Config{Labels: map[string]string{
			"org.opencontainers.image.builder": "Kaniko v1.20.0",
		}},
	})
	rt, _, _ := Detect(img)
	if rt != RuntimeKaniko {
		t.Errorf("rt = %q, want %q", rt, RuntimeKaniko)
	}
}

func TestDetectKanikoBySquashHeuristic(t *testing.T) {
	cf := v1.ConfigFile{
		History: []v1.History{
			{CreatedBy: "RUN apt-get update"},
			{CreatedBy: "RUN apt-get install -y curl"},
			{CreatedBy: "COPY app /app"},
			{CreatedBy: "ENV FOO=bar", EmptyLayer: true},
			{CreatedBy: "CMD [\"./app\"]", EmptyLayer: true},
			{CreatedBy: "RUN something"},
			{CreatedBy: "RUN something-else"},
		},
	}
	img := imageWithLayersAndConfig(t, 2, cf)
	rt, ev, err := Detect(img)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt != RuntimeKaniko {
		t.Errorf("rt = %q, want %q (squash heuristic)", rt, RuntimeKaniko)
	}
	if len(ev) == 0 || ev[0].Field != "heuristic.squash" {
		t.Errorf("ev = %+v, want heuristic.squash", ev)
	}
}

func TestDetectBuildKitByLabel(t *testing.T) {
	img := imageWithConfig(t, v1.ConfigFile{
		Config: v1.Config{Labels: map[string]string{
			"moby.buildkit.frontend": "dockerfile.v1",
		}},
	})
	rt, _, _ := Detect(img)
	if rt != RuntimeBuildKit {
		t.Errorf("rt = %q, want %q", rt, RuntimeBuildKit)
	}
}

func TestDetectBuildKitByHistoryFrontend(t *testing.T) {
	img := imageWithConfig(t, v1.ConfigFile{
		History: []v1.History{
			{CreatedBy: "buildkit.dockerfile.v0"},
		},
	})
	rt, _, _ := Detect(img)
	if rt != RuntimeBuildKit {
		t.Errorf("rt = %q, want %q", rt, RuntimeBuildKit)
	}
}

func TestDetectPodmanByContainersStorage(t *testing.T) {
	img := imageWithConfig(t, v1.ConfigFile{
		History: []v1.History{
			{CreatedBy: "containers-storage:foo"},
		},
	})
	rt, ev, _ := Detect(img)
	if rt != RuntimePodman {
		t.Errorf("rt = %q, want %q", rt, RuntimePodman)
	}
	if len(ev) == 0 || ev[0].Field == "" {
		t.Errorf("ev = %+v, want non-empty", ev)
	}
}

func TestDetectBuildahByAuthor(t *testing.T) {
	img := imageWithConfig(t, v1.ConfigFile{
		History: []v1.History{
			{Author: "Buildah", CreatedBy: "/bin/sh -c apt-get update"},
		},
	})
	rt, _, _ := Detect(img)
	if rt != RuntimeBuildah {
		t.Errorf("rt = %q, want %q", rt, RuntimeBuildah)
	}
}

func TestDetectBuildahByCreatedBy(t *testing.T) {
	img := imageWithConfig(t, v1.ConfigFile{
		History: []v1.History{
			{CreatedBy: "/usr/bin/buildah commit"},
		},
	})
	rt, _, _ := Detect(img)
	if rt != RuntimeBuildah {
		t.Errorf("rt = %q, want %q", rt, RuntimeBuildah)
	}
}

func TestDetectJibByLabel(t *testing.T) {
	img := imageWithConfig(t, v1.ConfigFile{
		Config: v1.Config{Labels: map[string]string{
			"jib.image.version": "3.4.1",
		}},
	})
	rt, _, _ := Detect(img)
	if rt != RuntimeJib {
		t.Errorf("rt = %q, want %q", rt, RuntimeJib)
	}
}

func TestDetectJibByHistoryLayerNames(t *testing.T) {
	img := imageWithConfig(t, v1.ConfigFile{
		History: []v1.History{
			{CreatedBy: "jib-dependencies"},
			{CreatedBy: "jib-classes"},
			{CreatedBy: "jib-resources"},
		},
	})
	rt, _, _ := Detect(img)
	if rt != RuntimeJib {
		t.Errorf("rt = %q, want %q", rt, RuntimeJib)
	}
}

func TestDetectKoByLabel(t *testing.T) {
	img := imageWithConfig(t, v1.ConfigFile{
		Config: v1.Config{Labels: map[string]string{
			"ko.build.commit": "abc123",
		}},
	})
	rt, _, _ := Detect(img)
	if rt != RuntimeKo {
		t.Errorf("rt = %q, want %q", rt, RuntimeKo)
	}
}

func TestDetectKoByEntrypointAndSourceLabel(t *testing.T) {
	img := imageWithConfig(t, v1.ConfigFile{
		Config: v1.Config{
			Entrypoint: []string{"/ko-app/myservice"},
			Labels: map[string]string{
				"org.opencontainers.image.source": "https://github.com/example/myservice",
			},
		},
	})
	rt, _, _ := Detect(img)
	if rt != RuntimeKo {
		t.Errorf("rt = %q, want %q", rt, RuntimeKo)
	}
}

func TestDetectPriorityBuildKitOverKaniko(t *testing.T) {
	// Both signals present; BuildKit wins because its detector runs
	// first.
	img := imageWithConfig(t, v1.ConfigFile{
		Author: "Kaniko",
		Config: v1.Config{Labels: map[string]string{
			"moby.buildkit.frontend": "dockerfile.v1",
		}},
	})
	rt, _, _ := Detect(img)
	if rt != RuntimeBuildKit {
		t.Errorf("rt = %q, want %q (buildkit must win over kaniko)", rt, RuntimeBuildKit)
	}
}

func TestDetectEvidenceIsNonEmpty(t *testing.T) {
	img := imageWithConfig(t, v1.ConfigFile{Author: "Kaniko"})
	_, ev, _ := Detect(img)
	if len(ev) == 0 {
		t.Fatal("evidence must not be empty when a detector matches")
	}
	if ev[0].Reason == "" || ev[0].Field == "" {
		t.Errorf("evidence missing fields: %+v", ev[0])
	}
}
