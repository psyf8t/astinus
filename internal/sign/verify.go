package sign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
)

// VerifyOptions configures a verification call. Mirrors
// SignOptions in shape so operators with the same Cosign setup
// pass the same arguments to sign + verify.
type VerifyOptions struct {
	// SBOMPath is the path to the SBOM file being verified
	// (sign-blob mode). Required when SignaturePath is set.
	SBOMPath string

	// SignaturePath is the detached signature blob path
	// (sign-blob mode).
	SignaturePath string

	// AttachedToImage is an OCI ref Cosign reads the
	// attestation back from. Mutually exclusive with
	// SignaturePath.
	AttachedToImage string

	// KeyPath is the public key path (key-based verification).
	KeyPath string

	// CertIdentityRegexp / CertOIDCIssuer scope keyless
	// verification to a specific OIDC identity (e.g. only
	// signatures from `^https://github\\.com/myorg/.*` repos).
	// Both must be set for keyless verification.
	CertIdentityRegexp string
	CertOIDCIssuer     string

	// Corporate Sigstore overrides — same shape as SignOptions.
	RekorURL  string
	FulcioURL string
	TUFMirror string
	CABundle  string
}

// Verifier wraps the cosign verification subcommands. Uses the
// same `cosign` binary lookup as CosignSigner.
type Verifier struct {
	cosignPath string
	logger     *slog.Logger
}

// NewVerifier returns a Verifier wrapping the cosign binary.
// Same fallback rules as NewCosignSigner: ErrTooling when cosign
// isn't in PATH.
func NewVerifier(opts CosignOptions) (*Verifier, error) {
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
	return &Verifier{cosignPath: resolved, logger: logger}, nil
}

// VerifyResult records the outcome of a successful verification.
// Returned alongside nil error; the cosign stdout is preserved
// for operators who want to inspect it.
type VerifyResult struct {
	Stdout     []byte
	VerifiedAt time.Time
}

// Verify runs the appropriate cosign verify subcommand per opts.
// Mode is inferred:
//
//   - sign-blob       — SBOMPath + SignaturePath set.
//   - verify-attestation — AttachedToImage set.
//
// Returns a wrapped ErrSigning on cosign non-zero exit (the error
// includes Cosign's stderr so operators see the real reason —
// "no matching signatures" / "expired certificate" / etc.).
func (v *Verifier) Verify(ctx context.Context, opts VerifyOptions) (*VerifyResult, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	args := buildVerifyArgs(opts)
	envExtra := buildVerifyEnv(opts)

	// G204: same risk-accept as CosignSigner.Sign — see ADR-0036.
	cmd := exec.CommandContext(ctx, v.cosignPath, args...) //nolint:gosec
	cmd.Env = append(os.Environ(), envExtra...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	v.logger.Info("verify.cosign.start",
		"binary", v.cosignPath,
		"args", maskSensitive(args),
		"rekor_url", opts.RekorURL,
		"fulcio_url", opts.FulcioURL)

	runErr := cmd.Run()
	elapsed := time.Since(start)

	if runErr != nil {
		v.logger.Warn("verify.cosign.failed",
			"binary", v.cosignPath,
			"duration", elapsed,
			"err", runErr.Error(),
			"stderr_tail", lastStderrLines(stderr.String(), 5))
		return nil, fmt.Errorf("%w: cosign verify: %w: %s", ErrSigning, runErr, stderr.String())
	}

	v.logger.Info("verify.cosign.success",
		"binary", v.cosignPath,
		"duration", elapsed)
	return &VerifyResult{
		Stdout:     stdout.Bytes(),
		VerifiedAt: time.Now().UTC(),
	}, nil
}

// validate enforces the same per-option invariants the CLI's flag
// parser would. Surfaced on the type so unit tests can call it
// directly.
func (opts VerifyOptions) validate() error {
	switch {
	case opts.AttachedToImage != "" && opts.SignaturePath != "":
		return errors.Join(ErrInvalidConfig,
			errors.New("--attached-to-image and --signature are mutually exclusive"))
	case opts.AttachedToImage == "" && opts.SignaturePath == "":
		return errors.Join(ErrInvalidConfig,
			errors.New("either --attached-to-image or --signature is required"))
	case opts.SignaturePath != "" && opts.SBOMPath == "":
		return errors.Join(ErrInvalidConfig,
			errors.New("--signature requires --sbom"))
	}
	hasKeyless := opts.CertIdentityRegexp != "" || opts.CertOIDCIssuer != ""
	if opts.KeyPath == "" && !hasKeyless {
		return errors.Join(ErrInvalidConfig,
			errors.New("either --key (key-based) or both --cert-identity-regexp + --cert-oidc-issuer (keyless) are required"))
	}
	if hasKeyless && (opts.CertIdentityRegexp == "" || opts.CertOIDCIssuer == "") {
		return errors.Join(ErrInvalidConfig,
			errors.New("keyless verification requires BOTH --cert-identity-regexp and --cert-oidc-issuer"))
	}
	return nil
}

// buildVerifyArgs assembles the cosign verify argv.
func buildVerifyArgs(opts VerifyOptions) []string {
	if opts.AttachedToImage != "" {
		return buildVerifyAttestationArgs(opts)
	}
	return buildVerifyBlobArgs(opts)
}

func buildVerifyBlobArgs(opts VerifyOptions) []string {
	args := []string{"verify-blob",
		"--signature", opts.SignaturePath,
	}
	args = appendCommonVerifyArgs(args, opts)
	args = append(args, opts.SBOMPath)
	return args
}

func buildVerifyAttestationArgs(opts VerifyOptions) []string {
	args := []string{"verify-attestation"}
	args = appendCommonVerifyArgs(args, opts)
	args = append(args, opts.AttachedToImage)
	return args
}

// appendCommonVerifyArgs adds the auth-method flags shared by
// both verify-blob and verify-attestation.
func appendCommonVerifyArgs(args []string, opts VerifyOptions) []string {
	if opts.KeyPath != "" {
		args = append(args, "--key", opts.KeyPath)
	}
	if opts.CertIdentityRegexp != "" {
		args = append(args, "--certificate-identity-regexp", opts.CertIdentityRegexp)
	}
	if opts.CertOIDCIssuer != "" {
		args = append(args, "--certificate-oidc-issuer", opts.CertOIDCIssuer)
	}
	return args
}

// buildVerifyEnv assembles the env vars cosign verify reads.
func buildVerifyEnv(opts VerifyOptions) []string {
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
	return env
}

// CosignVersion runs `cosign version` and returns the version
// string Cosign reports. Used by `astinus verify` for the helper
// banner so operators know which Cosign they're invoking. Returns
// ErrTooling when cosign isn't installed.
func CosignVersion(ctx context.Context, opts CosignOptions) (string, error) {
	v, err := NewVerifier(opts)
	if err != nil {
		return "", err
	}
	// G204: cosignPath was already resolved via exec.LookPath in
	// NewVerifier. See ADR-0036.
	cmd := exec.CommandContext(ctx, v.cosignPath, "version") //nolint:gosec
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: cosign version: %w", ErrSigning, err)
	}
	return strings.TrimSpace(string(out)), nil
}
