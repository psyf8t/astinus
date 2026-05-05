package sign

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
)

// defaultCosignBinary is the executable name we look up via
// `exec.LookPath`. Operators with non-PATH installations override
// via CosignOptions.CosignPath (or the CLI `--cosign-path` flag,
// reserved for future use).
const defaultCosignBinary = "cosign"

// CosignSigner wraps the `cosign` binary as a subprocess. See
// package doc for the rationale.
type CosignSigner struct {
	cosignPath string
	logger     *slog.Logger
}

// CosignOptions configures NewCosignSigner.
type CosignOptions struct {
	// CosignPath overrides the default `cosign` binary lookup.
	// Useful for tests (mock script) and for operators with
	// non-standard install paths.
	CosignPath string

	// Logger receives `sign.cosign.start` / `sign.cosign.success`
	// / `sign.cosign.failed` records. Nil → slog.Default.
	Logger *slog.Logger
}

// NewCosignSigner returns a Signer wrapping the `cosign` binary.
// Returns ErrTooling when the binary isn't available — callers
// branch on it to decide between fail-loud and warn-and-continue.
func NewCosignSigner(opts CosignOptions) (*CosignSigner, error) {
	path := opts.CosignPath
	if path == "" {
		path = defaultCosignBinary
	}
	resolved, err := exec.LookPath(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %q not in PATH (install cosign or set --cosign-path)", ErrTooling, path)
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &CosignSigner{cosignPath: resolved, logger: logger}, nil
}

// Name implements Signer.
func (*CosignSigner) Name() string { return "cosign" }

// Sign implements Signer. Builds the cosign argv per opts, writes
// the SBOM to a temp file (cosign reads from disk for `attest
// --predicate` and `sign-blob`), runs the subprocess, and returns
// the resulting Artifact.
//
// The temp file is removed after cosign exits (success or failure)
// so signing material doesn't linger on disk. cosign's own output
// (signature bundle / cert) lands in the operator-supplied
// OutputFile or in the OCI registry, never in the temp dir.
func (s *CosignSigner) Sign(ctx context.Context, sbom []byte, opts SignOptions) (*Artifact, error) {
	if err := opts.Validate(ModeForOptions(opts)); err != nil {
		return nil, err
	}

	tmp, cleanup, err := writeTempSBOM(sbom)
	if err != nil {
		return nil, fmt.Errorf("%w: write temp sbom: %w", ErrSigning, err)
	}
	defer cleanup()

	args := buildCosignArgs(tmp, opts)
	envExtra := buildCosignEnv(opts)

	// G204: cosign path is operator-supplied via --cosign-path
	// after `exec.LookPath` resolution; argv comes from the
	// per-call SignOptions (key path / image ref / tmp file). No
	// shell expansion happens. Documented as a deliberate
	// risk-accept in ADR-0036.
	cmd := exec.CommandContext(ctx, s.cosignPath, args...) //nolint:gosec // see ADR-0036
	cmd.Env = append(os.Environ(), envExtra...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	s.logger.Info("sign.cosign.start",
		"binary", s.cosignPath,
		"args", maskSensitive(args),
		"rekor_url", opts.RekorURL,
		"fulcio_url", opts.FulcioURL,
		"tuf_mirror", opts.TUFMirror,
		"attach_to_image", opts.AttachToImage,
		"output_file", opts.OutputFile)

	runErr := cmd.Run()
	elapsed := time.Since(start)

	if runErr != nil {
		s.logger.Warn("sign.cosign.failed",
			"binary", s.cosignPath,
			"duration", elapsed,
			"err", runErr.Error(),
			"stderr_tail", lastStderrLines(stderr.String(), 3))
		return nil, fmt.Errorf("%w: cosign: %w: %s", ErrSigning, runErr, stderr.String())
	}

	s.logger.Info("sign.cosign.success",
		"binary", s.cosignPath,
		"duration", elapsed,
		"stderr_lines", strings.Count(stderr.String(), "\n"))

	return &Artifact{
		Format:       artifactFormatFor(opts),
		Bytes:        stdout.Bytes(),
		OCIReference: opts.AttachToImage,
		PredicateURI: predicateURIFor(opts.Format),
		SignedAt:     time.Now().UTC(),
	}, nil
}

// ModeForOptions infers the Mode from opts. ModeCosignKey when
// KeyPath is non-empty, ModeCosignKeyless otherwise. Used by
// Validate so the caller doesn't have to plumb Mode separately.
func ModeForOptions(opts SignOptions) Mode {
	if opts.KeyPath != "" {
		return ModeCosignKey
	}
	return ModeCosignKeyless
}

// buildCosignArgs assembles the argv slice cosign expects. Two
// shapes:
//
//   - `cosign attest --predicate <sbom> --type <type> [--key <k>] --yes <image>`
//   - `cosign sign-blob --output-signature <out> [--key <k>] --yes <sbom>`
//
// `--yes` auto-confirms the keyless prompt; cosign's
// non-interactive default is to wait on stdin, which deadlocks in
// CI. The flag is harmless for key-based runs.
func buildCosignArgs(tmpSBOM string, opts SignOptions) []string {
	var args []string
	if opts.AttachToImage != "" {
		args = append(args,
			"attest",
			"--predicate", tmpSBOM,
			"--type", attestationTypeFor(opts.Format),
		)
		if opts.KeyPath != "" {
			args = append(args, "--key", opts.KeyPath)
		}
		args = append(args, "--yes", opts.AttachToImage)
		return args
	}
	args = append(args,
		"sign-blob",
		"--output-signature", opts.OutputFile,
	)
	if opts.KeyPath != "" {
		args = append(args, "--key", opts.KeyPath)
	}
	args = append(args, "--yes", tmpSBOM)
	return args
}

// buildCosignEnv assembles the env vars to add on top of the
// inherited process env. Empty values are skipped so cosign falls
// back to its defaults (public Sigstore instances).
func buildCosignEnv(opts SignOptions) []string {
	var env []string
	if opts.RekorURL != "" {
		env = append(env, "COSIGN_REKOR_URL="+opts.RekorURL)
	}
	if opts.FulcioURL != "" {
		env = append(env, "COSIGN_FULCIO_URL="+opts.FulcioURL)
	}
	if opts.TUFMirror != "" {
		env = append(env, "TUF_ROOT="+opts.TUFMirror)
	}
	if opts.CABundle != "" {
		env = append(env, "SSL_CERT_FILE="+opts.CABundle)
	}
	if opts.KeyPasswordEnv != "" {
		// cosign reads COSIGN_PASSWORD by default; when the
		// operator's password is in a differently-named env var
		// we forward it under cosign's expected name.
		if v := os.Getenv(opts.KeyPasswordEnv); v != "" {
			env = append(env, "COSIGN_PASSWORD="+v)
		}
	}
	return env
}

// writeTempSBOM writes sbom to a temp file and returns its path
// plus a cleanup function the caller defers. The file is
// 0600-mode so an SBOM that contains sensitive component data
// isn't world-readable while signing is in flight.
func writeTempSBOM(sbom []byte) (string, func(), error) {
	f, err := os.CreateTemp("", "astinus-sbom-*.json")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.Remove(f.Name()) }
	if _, err := f.Write(sbom); err != nil {
		_ = f.Close()
		cleanup()
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return f.Name(), cleanup, nil
}

// maskSensitive returns args with key paths and tokens redacted.
// Used in the `sign.cosign.start` log so a verbose-debug session
// doesn't leak operator key paths into the build log.
//
// Heuristic: any value following `--key` / `--token` / `--cert`
// / containing `password` is replaced with `<redacted>`. The
// flag name itself is kept so operators can still debug "why was
// --key not passed?" without seeing the key path.
func maskSensitive(args []string) []string {
	out := make([]string, len(args))
	skip := map[int]bool{}
	for i, a := range args {
		switch a {
		case "--key", "--cert", "--token", "--certificate":
			out[i] = a
			if i+1 < len(args) {
				skip[i+1] = true
			}
			continue
		}
		if skip[i] {
			out[i] = "<redacted>"
			continue
		}
		out[i] = a
	}
	return out
}

// lastStderrLines returns the last n non-empty lines of s,
// joined by `\n`. Used for the warn-log payload so operators see
// cosign's actual error message without the stderr being
// unbounded.
func lastStderrLines(s string, n int) string {
	if s == "" || n <= 0 {
		return ""
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	keep := make([]string, 0, n)
	for i := len(lines) - 1; i >= 0 && len(keep) < n; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			keep = append([]string{line}, keep...)
		}
	}
	return strings.Join(keep, "\n")
}

// artifactFormatFor identifies the artifact shape cosign produced.
func artifactFormatFor(opts SignOptions) string {
	if opts.AttachToImage != "" {
		return "in-toto-attestation"
	}
	return "cosign-bundle"
}
