package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// TestEnrichEndToEndRegistry pushes a hand-crafted layered image to
// an in-memory registry, runs `astinus enrich --sbom <file> --image
// <ref>`, and asserts the resulting CycloneDX has LayerInfo on every
// component with file evidence.
func TestEnrichEndToEndRegistry(t *testing.T) {
	host, stop := startInMemoryRegistry(t)
	defer stop()

	img := buildLayeredImage(t,
		map[string]string{"usr/bin/foo": "v1"},
		map[string]string{"opt/app/jq": "binary"},
	)
	pushImage(t, host, "team/app:v1", img)

	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.cdx.json")
	outPath := filepath.Join(dir, "out.cdx.json")

	sbomBody := []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "bom-ref": "comp-foo",
      "type": "library",
      "name": "foo",
      "version": "1.0",
      "evidence": {"occurrences": [{"location": "/usr/bin/foo"}]}
    },
    {
      "bom-ref": "comp-jq",
      "type": "application",
      "name": "jq",
      "version": "1.7.1",
      "evidence": {"occurrences": [{"location": "opt/app/jq"}]}
    },
    {
      "bom-ref": "no-evidence",
      "type": "library",
      "name": "ghost"
    }
  ]
}`)
	if err := os.WriteFile(sbomPath, sbomBody, 0o600); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	root := newRootCommand(&rootOptions{})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{
		"enrich",
		"--sbom", sbomPath,
		"--image", host + "/team/app:v1",
		"--insecure",
		"--output", outPath,
		"--output-format", "cyclonedx-json",
	})
	root.SetContext(context.Background())

	if err := root.Execute(); err != nil {
		t.Fatalf("enrich: %v", err)
	}

	body, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	var got struct {
		Metadata struct {
			Properties []struct{ Name, Value string } `json:"properties"`
		} `json:"metadata"`
		Components []struct {
			BOMRef     string                         `json:"bom-ref"`
			Properties []struct{ Name, Value string } `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, body)
	}

	stamp := propMap(got.Metadata.Properties)
	if stamp["astinus:enriched-by"] != "astinus" {
		t.Errorf("enriched-by stamp missing: %v", stamp)
	}

	want := map[string]bool{
		"comp-foo":    true,
		"comp-jq":     true,
		"no-evidence": false,
	}
	for _, c := range got.Components {
		mp := propMap(c.Properties)
		_, hasLayer := mp["astinus:layer:index"]
		if hasLayer != want[c.BOMRef] {
			t.Errorf("component %q hasLayer=%v want=%v (props=%v)",
				c.BOMRef, hasLayer, want[c.BOMRef], mp)
		}
	}
}

func TestEnrichRequiresFlags(t *testing.T) {
	root := newRootCommand(&rootOptions{})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"enrich"})

	if err := root.Execute(); err == nil {
		t.Fatal("expected error for missing required flags")
	}
}

func TestEnrichRejectsSPDXInput(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.spdx.json")
	body := []byte(`{"spdxVersion":"SPDX-2.3","name":"x","SPDXID":"SPDXRef-DOCUMENT"}`)
	if err := os.WriteFile(sbomPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	root := newRootCommand(&rootOptions{})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{
		"enrich",
		"--sbom", sbomPath,
		"--image", "ghcr.io/foo:latest",
	})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for SPDX input (Stage 7 territory)")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────

func startInMemoryRegistry(t *testing.T) (string, func()) {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	u, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}
	return u.Host, srv.Close
}

func pushImage(t *testing.T, host, ref string, img v1.Image) {
	t.Helper()
	tag, err := name.NewTag(host+"/"+ref, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(tag, img); err != nil {
		t.Fatalf("remote.Write: %v", err)
	}
}

func buildLayeredImage(t *testing.T, layers ...map[string]string) v1.Image {
	t.Helper()
	img := empty.Image
	for _, files := range layers {
		layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(buildTar(t, files))), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		img, err = mutate.AppendLayers(img, layer)
		if err != nil {
			t.Fatal(err)
		}
	}
	return img
}

func buildTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for path, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:     path,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func propMap(props []struct{ Name, Value string }) map[string]string {
	out := map[string]string{}
	for _, p := range props {
		out[p.Name] = p.Value
	}
	return out
}
