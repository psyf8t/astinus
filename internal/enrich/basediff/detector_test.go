package basediff

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestDetectFromLabelsPrimary(t *testing.T) {
	cfg := &v1.ConfigFile{}
	cfg.Config.Labels = map[string]string{
		"org.opencontainers.image.base.name": "alpine:3.19",
	}
	if got := detectFromLabels(cfg); got != "alpine:3.19" {
		t.Errorf("got %q", got)
	}
}

func TestDetectFromLabelsCombinesDigest(t *testing.T) {
	cfg := &v1.ConfigFile{}
	cfg.Config.Labels = map[string]string{
		"org.opencontainers.image.base.name":   "alpine:3.19",
		"org.opencontainers.image.base.digest": "sha256:abcd",
	}
	if got := detectFromLabels(cfg); got != "alpine:3.19@sha256:abcd" {
		t.Errorf("got %q", got)
	}
}

func TestDetectFromLabelsRespectsExistingDigest(t *testing.T) {
	cfg := &v1.ConfigFile{}
	cfg.Config.Labels = map[string]string{
		"org.opencontainers.image.base.name":   "alpine@sha256:cafe",
		"org.opencontainers.image.base.digest": "sha256:abcd",
	}
	if got := detectFromLabels(cfg); got != "alpine@sha256:cafe" {
		t.Errorf("digest in name should be preserved: got %q", got)
	}
}

func TestDetectFromLabelsFallbackKey(t *testing.T) {
	cfg := &v1.ConfigFile{}
	cfg.Config.Labels = map[string]string{
		"org.opencontainers.image.base.ref.name": "alpine:3.19",
	}
	if got := detectFromLabels(cfg); got != "alpine:3.19" {
		t.Errorf("got %q", got)
	}
}

func TestDetectFromLabelsEmpty(t *testing.T) {
	cfg := &v1.ConfigFile{}
	if got := detectFromLabels(cfg); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
	if got := detectFromLabels(nil); got != "" {
		t.Errorf("nil cfg should yield empty, got %q", got)
	}
}
