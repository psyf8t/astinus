//go:build acceptance

package helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// EnrichOpts is the Sprint-3-specific shape of `astinus enrich`
// arguments the acceptance suite cares about. The parent
// `test/acceptance/helpers.AstinusOpts` only knows about CPE-era
// flags; Sprint 3 adds registry / lifecycle / signing flags + a way
// to disable the Sprint 3 enrichers via --disable for negative tests.
type EnrichOpts struct {
	SBOM         string
	Image        string
	Output       string
	OutputFormat string

	// Stage 4 — registry / mirrors.
	NoRegistry       bool
	MirrorsConfig    string
	RegistryCacheDir string

	// Stage 5 — lifecycle.
	NoLifecycle       bool
	LifecycleMode     string
	LifecycleSnapshot string

	// Stage 6 — signing.
	SignWith              string
	SigningKey            string
	SigningKeyPasswordEnv string
	SignatureOutput       string
	AttachToImage         string
	RekorURL              string
	FulcioURL             string
	TUFMirror             string
	CosignPath            string

	// Networking / corporate environment.
	NoNetwork bool
	CACert    string

	// Compliance gate.
	FailOn           string
	ComplianceConfig string

	// Plumbed through verbatim — escape hatch for flags this struct
	// hasn't grown yet.
	Extra []string

	// Env, if non-nil, replaces the inherited environment for the
	// astinus subprocess. Used by the no-PROXY-leak test that needs
	// a guaranteed-clean env.
	Env []string
}

// EnrichResult is the parsed result of one `astinus enrich` run.
type EnrichResult struct {
	BOM      *cdx.BOM
	OutPath  string
	Stdout   string
	Stderr   string
	ExitCode int
}

// RunEnrich invokes the locally-built astinus binary with the given
// opts. Caller checks ExitCode for the expected outcome — RunEnrich
// does NOT tb.Fatalf on non-zero exit, because compliance-gate /
// signing tests assert on specific non-zero exits. Use RunEnrichOK
// for the happy-path cases.
func RunEnrich(tb testing.TB, opts EnrichOpts) *EnrichResult {
	tb.Helper()
	bin := AstinusBinary(tb)
	out := opts.Output
	if out == "" {
		out = filepath.Join(tb.TempDir(), "out.cdx.json")
	}
	// Auto-materialise a minimal OCI layout when the operator passes
	// a logical-name Image (e.g. "test/foo:1.0") — Sprint 3 tests
	// don't care about image content, only that the binary doesn't
	// hard-fail on registry-pull. A real registry / docker / oci ref
	// is left alone.
	if opts.Image != "" && !hasImageScheme(opts.Image) {
		opts.Image = MinimalOCIImage(tb, "")
	}
	args := buildEnrichArgs(opts, out)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // bin from AstinusBinary, args internal
	if opts.Env != nil {
		cmd.Env = opts.Env
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := &EnrichResult{
		OutPath: out,
		Stdout:  stdout.String(),
		Stderr:  stderr.String(),
	}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if err != nil && cmd.ProcessState == nil {
		tb.Fatalf("astinus enrich failed to launch: %v", err)
	}
	if res.ExitCode == 0 {
		res.BOM = readBOMOrNil(tb, out)
	}
	return res
}

// RunEnrichOK is the happy-path wrapper — tb.Fatalf on non-zero exit.
func RunEnrichOK(tb testing.TB, opts EnrichOpts) *EnrichResult {
	tb.Helper()
	res := RunEnrich(tb, opts)
	if res.ExitCode != 0 {
		tb.Fatalf("astinus enrich exited %d\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}
	return res
}

// RunVerify invokes `astinus verify` with the given args.
func RunVerify(tb testing.TB, args ...string) *EnrichResult {
	tb.Helper()
	bin := AstinusBinary(tb)
	full := append([]string{"verify"}, args...)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, full...) //nolint:gosec // bin from AstinusBinary
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := &EnrichResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if err != nil && cmd.ProcessState == nil {
		tb.Fatalf("astinus verify failed to launch: %v", err)
	}
	return res
}

// astinusBinaryOnce caches the binary path across all tests in the
// process — `go build` is the dominant cost in the suite.
var (
	astinusBinaryOnce sync.Once
	astinusBinaryPath string
	astinusBinaryErr  error
)

// AstinusBinary builds (once) and returns the absolute path to the
// astinus binary. The binary lives under the test's runtime tempdir
// so concurrent `go test` invocations don't clobber each other.
func AstinusBinary(tb testing.TB) string {
	tb.Helper()
	astinusBinaryOnce.Do(func() {
		root := repoRoot(tb)
		dir, err := os.MkdirTemp("", "astinus-acceptance-bin-")
		if err != nil {
			astinusBinaryErr = err
			return
		}
		out := filepath.Join(dir, "astinus")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "build", "-o", out, filepath.Join(root, "cmd", "astinus"))
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		if err := cmd.Run(); err != nil {
			astinusBinaryErr = err
			return
		}
		astinusBinaryPath = out
	})
	if astinusBinaryErr != nil {
		tb.Fatalf("build astinus binary: %v", astinusBinaryErr)
	}
	return astinusBinaryPath
}

// buildEnrichArgs is the flag-mapping core. Kept separate so a unit
// test could exercise it without forking a process. Cognitive
// complexity is high by design — every CLI flag this suite cares
// about is one branch — and the alternative (reflection or struct
// tags) is harder to read than the obvious if-tree.
//
//nolint:gocognit,gocyclo // see comment above
func buildEnrichArgs(opts EnrichOpts, out string) []string {
	args := []string{"enrich"}
	args = append(args, "--sbom", opts.SBOM)
	if opts.Image != "" {
		args = append(args, "--image", opts.Image)
	}
	args = append(args, "--output", out)
	if opts.OutputFormat == "" {
		args = append(args, "--output-format", "cyclonedx-json")
	} else {
		args = append(args, "--output-format", opts.OutputFormat)
	}
	if opts.NoRegistry {
		args = append(args, "--no-registry")
	}
	if opts.MirrorsConfig != "" {
		args = append(args, "--mirrors-config", opts.MirrorsConfig)
	}
	if opts.RegistryCacheDir != "" {
		args = append(args, "--registry-cache-dir", opts.RegistryCacheDir)
	}
	if opts.NoLifecycle {
		args = append(args, "--no-lifecycle")
	}
	if opts.LifecycleMode != "" {
		args = append(args, "--lifecycle-mode", opts.LifecycleMode)
	}
	if opts.LifecycleSnapshot != "" {
		args = append(args, "--lifecycle-snapshot", opts.LifecycleSnapshot)
	}
	if opts.SignWith != "" {
		args = append(args, "--sign-with", opts.SignWith)
	}
	if opts.SigningKey != "" {
		args = append(args, "--signing-key", opts.SigningKey)
	}
	if opts.SigningKeyPasswordEnv != "" {
		args = append(args, "--signing-key-password-env", opts.SigningKeyPasswordEnv)
	}
	if opts.SignatureOutput != "" {
		args = append(args, "--signature-output", opts.SignatureOutput)
	}
	if opts.AttachToImage != "" {
		args = append(args, "--attach-to-image", opts.AttachToImage)
	}
	if opts.RekorURL != "" {
		args = append(args, "--rekor-url", opts.RekorURL)
	}
	if opts.FulcioURL != "" {
		args = append(args, "--fulcio-url", opts.FulcioURL)
	}
	if opts.TUFMirror != "" {
		args = append(args, "--tuf-mirror", opts.TUFMirror)
	}
	if opts.CosignPath != "" {
		args = append(args, "--cosign-path", opts.CosignPath)
	}
	if opts.NoNetwork {
		args = append(args, "--no-network")
	}
	if opts.CACert != "" {
		args = append(args, "--ca-cert", opts.CACert)
	}
	if opts.FailOn != "" {
		args = append(args, "--fail-on", opts.FailOn)
	}
	if opts.ComplianceConfig != "" {
		args = append(args, "--compliance-config", opts.ComplianceConfig)
	}
	args = append(args, opts.Extra...)
	return args
}

// readBOMOrNil reads the output BOM if it exists; returns nil
// silently when the run produced no output (signing-failure paths
// may still emit a BOM, but tests use ExitCode for the verdict).
func readBOMOrNil(tb testing.TB, path string) *cdx.BOM {
	tb.Helper()
	body, err := os.ReadFile(path) //nolint:gosec // path from tb.TempDir
	if err != nil {
		return nil
	}
	var bom cdx.BOM
	if err := json.Unmarshal(body, &bom); err != nil {
		tb.Fatalf("decode BOM %s: %v", path, err)
	}
	return &bom
}

// hasImageScheme reports whether ref starts with one of the schemes
// astinus's image source recognises as "no registry pull needed".
// Astinus's `refRequiresNetwork` heuristic is the source of truth;
// we mirror it here to avoid hand-editing every test fixture's
// `--image` value.
func hasImageScheme(ref string) bool {
	for _, scheme := range []string{
		"archive://", "oci://", "docker-daemon://", "podman-daemon://",
	} {
		if strings.HasPrefix(ref, scheme) {
			return true
		}
	}
	return false
}

// repoRoot walks up from this file until go.mod is found.
func repoRoot(tb testing.TB) string {
	tb.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			tb.Fatalf("repoRoot: could not find go.mod above %s", file)
		}
		dir = parent
	}
}
