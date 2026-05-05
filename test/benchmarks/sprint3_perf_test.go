//go:build benchmark

package benchmarks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkRegistryEnrichment_LocalMirror — measures astinus enrich
// throughput when the npm mirror is in-process (httptest.Server in
// the same OS) so the benchmark isolates the registry-fetch
// overhead, not the network. Useful for tracking regressions in
// the Sprint 3 Task 4 cache + transport layer.
//
// Reports allocs/op and ms/op. The 100-component SBOM is a
// realistic small-app size; bigger inputs would be dominated by
// SBOM parse time, not registry fetch.
func BenchmarkRegistryEnrichment_LocalMirror(b *testing.B) {
	bin := buildAstinusBinary(b)

	const componentCount = 100
	sbom := generateNpmSBOM(b, componentCount)
	mirror := startMirror(b, componentCount)
	cfg := writeMirrorConfig(b, mirror.URL)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out := filepath.Join(b.TempDir(), "out.cdx.json")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		cmd := exec.CommandContext(ctx, bin,
			"enrich",
			"--sbom", sbom,
			"--image", "bench/registry:1.0",
			"--output", out,
			"--output-format", "cyclonedx-json",
			"--mirrors-config", cfg,
			"--no-network", // network is the in-process mirror; this prevents extra outbound DNS
			"--disable", "layer",
			"--disable", "evidence",
		)
		if err := cmd.Run(); err != nil {
			b.Fatalf("enrich: %v", err)
		}
		cancel()
	}

	b.ReportMetric(float64(atomic.LoadInt64(&mirror.requests))/float64(b.N), "requests/op")
}

// BenchmarkLifecycleEnricher_BundledOnly — measures the lifecycle
// enricher's cost when running against the bundled snapshot only
// (--no-network). The bundled snapshot is in-memory after first load,
// so this benchmark tracks regression of the per-component matcher.
func BenchmarkLifecycleEnricher_BundledOnly(b *testing.B) {
	bin := buildAstinusBinary(b)
	sbom := generateRuntimeSBOM(b, 50)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out := filepath.Join(b.TempDir(), "out.cdx.json")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, bin,
			"enrich",
			"--sbom", sbom,
			"--image", "bench/lifecycle:1.0",
			"--output", out,
			"--output-format", "cyclonedx-json",
			"--no-network",
			"--disable", "layer",
			"--disable", "evidence",
		)
		if err := cmd.Run(); err != nil {
			b.Fatalf("enrich: %v", err)
		}
		cancel()
	}
}

// ─── benchmark fixtures (no helpers package — keeps benchmark
//                          build tag isolated from acceptance tag) ───

type benchMirror struct {
	URL      string
	requests int64
	server   *httptest.Server
}

func startMirror(b *testing.B, n int) *benchMirror {
	b.Helper()
	m := &benchMirror{}
	const payload = `{"name":"x","version":"1","license":"MIT","description":"benchmark fixture"}`
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&m.requests, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}))
	m.URL = m.server.URL
	b.Cleanup(m.server.Close)
	_ = n
	return m
}

func generateNpmSBOM(b *testing.B, n int) string {
	b.Helper()
	var sb strings.Builder
	sb.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"type":"library","name":"pkg`)
		sb.WriteString(itoa(i))
		sb.WriteString(`","version":"1.0.0","purl":"pkg:npm/pkg`)
		sb.WriteString(itoa(i))
		sb.WriteString(`@1.0.0"}`)
	}
	sb.WriteString(`]}`)
	path := filepath.Join(b.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		b.Fatalf("write sbom: %v", err)
	}
	return path
}

func generateRuntimeSBOM(b *testing.B, n int) string {
	b.Helper()
	products := []string{"nodejs", "python", "debian", "alpine", "ubuntu", "openjdk"}
	var sb strings.Builder
	sb.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		p := products[i%len(products)]
		sb.WriteString(`{"type":"application","name":"`)
		sb.WriteString(p)
		sb.WriteString(`","version":"1.0","purl":"pkg:generic/`)
		sb.WriteString(p)
		sb.WriteString(`@1.0"}`)
	}
	sb.WriteString(`]}`)
	path := filepath.Join(b.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		b.Fatalf("write sbom: %v", err)
	}
	return path
}

func writeMirrorConfig(b *testing.B, url string) string {
	b.Helper()
	body := `version: 1
mirrors:
  - ecosystem: npm
    url: ` + url + `
    mode: replace
`
	path := filepath.Join(b.TempDir(), "mirrors.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		b.Fatalf("write mirrors: %v", err)
	}
	return path
}

func buildAstinusBinary(b *testing.B) string {
	b.Helper()
	root := repoRootBench(b)
	out := filepath.Join(b.TempDir(), "astinus")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", out, filepath.Join(root, "cmd", "astinus"))
	if out, err := cmd.CombinedOutput(); err != nil {
		b.Fatalf("go build astinus: %v\n%s", err, out)
	}
	return out
}

func repoRootBench(b *testing.B) string {
	b.Helper()
	dir, err := os.Getwd()
	if err != nil {
		b.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			b.Fatalf("repoRoot: no go.mod above %s", dir)
		}
		dir = parent
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [16]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
