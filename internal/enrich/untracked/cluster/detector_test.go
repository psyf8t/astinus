package cluster

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// ─── DetectClusters ────────────────────────────────────────────────

func TestDetectClustersNilImage(t *testing.T) {
	if _, err := DetectClusters(context.Background(), nil, Options{}); err == nil {
		t.Fatal("expected error for nil image")
	}
}

func TestDetectClustersNPMSinglePackage(t *testing.T) {
	img := buildLayered(t, map[string]string{
		"app/node_modules/lodash/package.json": `{"name":"lodash","version":"4.17.21"}`,
		"app/node_modules/lodash/index.js":     `module.exports = {};`,
		"app/node_modules/lodash/lib/foo.js":   `// foo`,
		"app/node_modules/lodash/lib/bar.js":   `// bar`,
		"app/node_modules/lodash/test/spec.js": `// spec`,
	})

	clusters, err := DetectClusters(context.Background(), img, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(clusters) != 1 {
		t.Fatalf("len(clusters) = %d, want 1", len(clusters))
	}
	c := clusters[0]
	if c.Identity.Name != "lodash" {
		t.Errorf("Name = %q", c.Identity.Name)
	}
	if c.Identity.PURL != "pkg:npm/lodash@4.17.21" {
		t.Errorf("PURL = %q", c.Identity.PURL)
	}
	if got := len(c.Files); got != 5 {
		t.Errorf("Files count = %d, want 5", got)
	}
}

// TestDetectClustersNestedNodeModules — nested package.json under
// foo's node_modules must produce its own cluster, and foo must NOT
// claim files that belong to the nested cluster.
func TestDetectClustersNestedNodeModules(t *testing.T) {
	img := buildLayered(t, map[string]string{
		"app/node_modules/foo/package.json":                  `{"name":"foo","version":"1.0.0"}`,
		"app/node_modules/foo/index.js":                      `// foo entry`,
		"app/node_modules/foo/node_modules/bar/package.json": `{"name":"bar","version":"2.0.0"}`,
		"app/node_modules/foo/node_modules/bar/index.js":     `// bar entry`,
		"app/node_modules/foo/node_modules/bar/lib/util.js":  `// util`,
	})

	clusters, err := DetectClusters(context.Background(), img, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(clusters) != 2 {
		t.Fatalf("len(clusters) = %d, want 2", len(clusters))
	}
	foo := findCluster(clusters, "foo")
	bar := findCluster(clusters, "bar")
	if foo == nil || bar == nil {
		t.Fatalf("expected foo + bar, got %v", names(clusters))
	}
	for _, p := range foo.Files {
		if strings.Contains(p, "/node_modules/bar/") {
			t.Errorf("foo cluster wrongly claimed nested file: %s", p)
		}
	}
	if !containsPath(bar.Files, "app/node_modules/foo/node_modules/bar/index.js") {
		t.Error("bar cluster missing its index.js")
	}
}

func TestDetectClustersDensityExtractedTarball(t *testing.T) {
	files := map[string]string{
		"opt/extracted/sqlite-3.44.0/Makefile":         "all:",
		"opt/extracted/sqlite-3.44.0/configure":        "#!/bin/sh",
		"opt/extracted/sqlite-3.44.0/README":           "sqlite",
		"opt/extracted/sqlite-3.44.0/LICENSE":          "blessed-license",
		"opt/extracted/sqlite-3.44.0/src/sqlite3.c":    "code",
		"opt/extracted/sqlite-3.44.0/src/sqlite3.h":    "header",
		"opt/extracted/sqlite-3.44.0/include/sqlite.h": "decl",
		"opt/extracted/sqlite-3.44.0/test/test1.c":     "test",
	}
	// Pad up the file count so the >100 / >1000 bonuses kick in.
	for i := 0; i < 1100; i++ {
		files[strJoin("opt/extracted/sqlite-3.44.0/src/auto/file", i, ".c")] = "x"
	}
	img := buildLayered(t, files)

	clusters, err := DetectClusters(context.Background(), img, Options{})
	if err != nil {
		t.Fatal(err)
	}
	sqlite := findCluster(clusters, "sqlite")
	if sqlite == nil {
		t.Fatalf("density did not detect sqlite cluster; got %v", names(clusters))
	}
	if sqlite.Identity.Version != "3.44.0" {
		t.Errorf("Version = %q, want 3.44.0", sqlite.Identity.Version)
	}
	if sqlite.Identity.Type != "generic" {
		t.Errorf("Type = %q, want generic", sqlite.Identity.Type)
	}
	if sqlite.Identity.Confidence < 0.7 {
		t.Errorf("Confidence = %v, want ≥ 0.7", sqlite.Identity.Confidence)
	}
	if got := len(sqlite.Files); got < 1000 {
		t.Errorf("Files count = %d, want ≥ 1000", got)
	}
}

func TestDetectClustersAmbiguousDirectoryDoesNotCluster(t *testing.T) {
	img := buildLayered(t, map[string]string{
		"etc/passwd":   "root:x:0:0:",
		"etc/hostname": "host",
		"etc/foo.conf": "",
	})
	clusters, err := DetectClusters(context.Background(), img, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(clusters) != 0 {
		t.Errorf("/etc/ should not produce clusters; got %v", names(clusters))
	}
}

func TestDetectClustersSkipDensityOption(t *testing.T) {
	img := buildLayered(t, map[string]string{
		"opt/extracted/sqlite-3.44.0/Makefile":  "x",
		"opt/extracted/sqlite-3.44.0/configure": "x",
		"opt/extracted/sqlite-3.44.0/README":    "x",
		"opt/extracted/sqlite-3.44.0/LICENSE":   "x",
		"opt/extracted/sqlite-3.44.0/src/x.c":   "x",
	})
	clusters, _ := DetectClusters(context.Background(), img, Options{SkipDensity: true})
	if len(clusters) != 0 {
		t.Errorf("SkipDensity=true should suppress density clusters; got %v", names(clusters))
	}
}

func TestDetectClustersPythonWheel(t *testing.T) {
	img := buildLayered(t, map[string]string{
		"site-packages/requests-2.31.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n",
		"site-packages/requests-2.31.0.dist-info/RECORD":   "...",
		"site-packages/requests/__init__.py":               "import x",
		"site-packages/requests/api.py":                    "def get(): pass",
	})
	clusters, _ := DetectClusters(context.Background(), img, Options{})
	if len(clusters) != 1 {
		t.Fatalf("want 1 cluster, got %d (%v)", len(clusters), names(clusters))
	}
	if clusters[0].Identity.Name != "requests" {
		t.Errorf("Name = %q", clusters[0].Identity.Name)
	}
	// dist-info METADATA must claim the package's parent dir, so
	// it covers the requests/ source tree as well.
	if !containsPath(clusters[0].Files, "site-packages/requests/api.py") {
		t.Errorf("cluster did not claim site-packages/requests/api.py: files=%v",
			clusters[0].Files)
	}
}

// ─── Helpers ────────────────────────────────────────────────────────

func buildLayered(t *testing.T, files map[string]string) v1.Image {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for p, c := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: p, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(c)); err != nil {
			t.Fatal(err)
		}
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
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func findCluster(cs []Cluster, name string) *Cluster {
	for i := range cs {
		if cs[i].Identity.Name == name {
			return &cs[i]
		}
	}
	return nil
}

func names(cs []Cluster) []string {
	out := make([]string, len(cs))
	for i := range cs {
		out[i] = cs[i].Identity.Name
	}
	return out
}

func containsPath(s []string, p string) bool {
	for _, x := range s {
		if x == p {
			return true
		}
	}
	return false
}

// strJoin assembles "<a>NN<b>" for fixture-padding paths.
func strJoin(a string, n int, b string) string {
	var sb strings.Builder
	sb.WriteString(a)
	if n < 10 {
		sb.WriteString("000")
	} else if n < 100 {
		sb.WriteString("00")
	} else if n < 1000 {
		sb.WriteString("0")
	}
	for _, c := range []byte(itoa(n)) {
		sb.WriteByte(c)
	}
	sb.WriteString(b)
	return sb.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// ─── Within / Identity helpers (fast unit) ─────────────────────────

func TestClusterWithin(t *testing.T) {
	c := &Cluster{Root: "app/node_modules/foo"}
	cases := map[string]bool{
		"app/node_modules/foo":          true,
		"app/node_modules/foo/index.js": true,
		"app/node_modules/foo/lib/x.js": true,
		"app/node_modules/food":         false, // prefix, no `/` separator
		"app/node_modules/bar/index.js": false,
	}
	for p, want := range cases {
		if got := c.Within(p); got != want {
			t.Errorf("Within(%q) = %v, want %v", p, got, want)
		}
	}
}
