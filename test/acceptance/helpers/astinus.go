package helpers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// AstinusOpts mirrors the spec's AstinusOpts struct. Empty fields
// fall back to safe defaults: Mode "hybrid", FailOn "" (no gate).
type AstinusOpts struct {
	SBOM      string
	Image     string
	Mode      string
	FailOn    string
	Disable   []string
	Enable    []string
	NoNetwork bool
	OfflineDB string
	Extra     []string
}

// RunAstinusFull invokes the locally-built astinus binary on the
// given image + SBOM and returns the parsed CycloneDX BOM. The
// binary is rebuilt once per test process (lazy init); reusing it
// across t.Run subtests keeps the matrix tests fast.
func RunAstinusFull(t TB, opts AstinusOpts) *cdx.BOM {
	t.Helper()
	bin := buildAstinusBinary(t)
	out := filepath.Join(t.TempDir(), "astinus.cdx.json")
	args := []string{
		"enrich",
		"--sbom", opts.SBOM,
		"--image", opts.Image,
		"--output", out,
		"--output-format", "cyclonedx-json",
	}
	if opts.Mode != "" {
		args = append(args, "--cpe-mode", opts.Mode)
	}
	if opts.FailOn != "" {
		args = append(args, "--fail-on", opts.FailOn)
	}
	if opts.NoNetwork {
		args = append(args, "--no-network")
	}
	if opts.OfflineDB != "" {
		args = append(args, "--offline-db", opts.OfflineDB)
	}
	for _, e := range opts.Enable {
		args = append(args, "--enable", e)
	}
	for _, d := range opts.Disable {
		args = append(args, "--disable", d)
	}
	args = append(args, opts.Extra...)
	RunOK(t, bin, args...)
	return ReadBOM(t, out)
}

// ReadBOM unmarshals a CycloneDX-JSON file from disk.
func ReadBOM(t TB, path string) *cdx.BOM {
	t.Helper()
	body, err := os.ReadFile(path) //nolint:gosec // path comes from t.TempDir
	if err != nil {
		t.Fatalf("read BOM %s: %v", path, err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(body, &bom); err != nil {
		t.Fatalf("decode BOM %s: %v", path, err)
	}
	return &bom
}

// SaveJSON dumps v as pretty-printed JSON to path.
func SaveJSON(t TB, path string, v any) {
	t.Helper()
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil { //nolint:gosec
		t.Fatalf("write %s: %v", path, err)
	}
}

// buildAstinusBinary locates (or builds) the astinus binary. The
// repo root is found by walking up from runtime.Caller(0) until
// `go.mod` is seen; the binary is then placed under the test's
// temp dir so concurrent tests don't fight over a shared bin/.
func buildAstinusBinary(t TB) string {
	t.Helper()
	root := repoRoot(t)
	out := filepath.Join(t.TempDir(), "astinus-acceptance-bin")
	RunOK(t, "go", "build", "-o", out, filepath.Join(root, "cmd", "astinus"))
	return out
}

// RepoCmdAstinus returns the absolute path to the cmd/astinus
// package — exposed so tests building bespoke binaries (e.g. with
// custom flags) can hand the right path to `go build`.
func RepoCmdAstinus(t TB) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "cmd", "astinus")
}

// repoRoot walks up from this file's location until go.mod is found.
func repoRoot(t TB) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("repoRoot: could not find go.mod above %s", file)
		}
		dir = parent
	}
}

// SplitCSVFlag splits a "a,b,c" string into a slice, trimming spaces.
// Used by tests that want to express enable / disable lists more
// compactly than slice literals.
func SplitCSVFlag(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
