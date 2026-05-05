package sign

import (
	"context"
	"errors"
	"time"
)

// Signer attaches a cryptographic signature / attestation to an
// SBOM. Today the only implementation is `CosignSigner`; the
// interface stays small so a future Go-library implementation
// (when sigstore-go's footprint shrinks) can land without
// changing call sites.
//
// Concurrency: implementations MUST be safe for concurrent Sign
// calls. The Cosign wrapper achieves this by giving each call its
// own temporary file + its own subprocess.
type Signer interface {
	// Name is the short identifier stamped onto Artifact.Format
	// and the `sign.complete` log line.
	Name() string

	// Sign produces an Artifact for the supplied SBOM bytes per
	// opts. Returns an error wrapping ErrTooling when the
	// underlying tool is unavailable so the caller can decide
	// between "fail loudly" and "warn + continue".
	Sign(ctx context.Context, sbom []byte, opts SignOptions) (*Artifact, error)
}

// Mode selects the signing flow. The CLI's `--sign-with` flag is
// translated to one of these values.
type Mode string

// Recognised modes.
const (
	// ModeNone disables signing (the CLI default).
	ModeNone Mode = ""

	// ModeCosignKey produces a key-based signature. SignOptions
	// must carry KeyPath; the password is read from the env var
	// named in KeyPasswordEnv (Cosign's COSIGN_PASSWORD by
	// default).
	ModeCosignKey Mode = "cosign-key"

	// ModeCosignKeyless produces a keyless signature using the
	// OIDC token Cosign auto-detects from the CI environment
	// (GITHUB_TOKEN, etc.). The Sigstore public infrastructure
	// is the default; corporate operators override via
	// SignOptions.RekorURL / FulcioURL / TUFMirror.
	ModeCosignKeyless Mode = "cosign-keyless"
)

// IsKnown reports whether m is a recognised mode value.
func (m Mode) IsKnown() bool {
	switch m {
	case ModeNone, ModeCosignKey, ModeCosignKeyless:
		return true
	default:
		return false
	}
}

// SignOptions are the per-call inputs the Signer consumes.
// (`sign.Options` would collide with `sign.CosignOptions` —
// constructor-time options vs per-call options. The mild stutter
// is the lesser evil.)
//
//nolint:revive // see comment above
type SignOptions struct {
	// Format is the SBOM format ("cyclonedx" / "spdx") so the
	// signer picks the right in-toto predicate type when
	// attaching to an image.
	Format string

	// AttachToImage is an OCI reference (e.g. `myorg/img:v1`)
	// to which Cosign attaches the in-toto attestation. Empty
	// means "produce a detached signature only".
	AttachToImage string

	// OutputFile is the path where Cosign writes the detached
	// signature blob. Required when AttachToImage is empty.
	OutputFile string

	// KeyPath is the Cosign private key file path used by
	// ModeCosignKey. Empty under ModeCosignKeyless.
	KeyPath string

	// KeyPasswordEnv is the env var holding the private key's
	// password. Cosign defaults to COSIGN_PASSWORD; operators
	// using a different name set it here.
	KeyPasswordEnv string

	// RekorURL / FulcioURL / TUFMirror are the corporate
	// Sigstore overrides. Empty means "use the public Sigstore
	// instance Cosign defaults to".
	RekorURL  string
	FulcioURL string
	TUFMirror string

	// CABundle is an optional path to a corporate CA PEM file
	// passed to Cosign via SSL_CERT_FILE so internal Rekor /
	// Fulcio / TUF endpoints behind a private CA validate.
	CABundle string
}

// Artifact is the signing result returned to the caller. Bytes is
// non-nil only for detached-signature modes; for image
// attestations the artifact lives in the OCI registry and the
// caller surfaces only the metadata.
type Artifact struct {
	// Format identifies the artifact shape ("cosign-bundle" /
	// "in-toto-attestation").
	Format string

	// Bytes is the raw signature payload (detached-mode only).
	// Nil when AttachToImage was set — the artifact lives in the
	// OCI registry under `<image>:<digest>.sig`.
	Bytes []byte

	// OCIReference is the OCI ref the attestation was attached
	// to (image-attached mode). Empty in detached mode.
	OCIReference string

	// PredicateURI is the in-toto predicate type URI for
	// attestations (`https://cyclonedx.org/bom/v1.6` or
	// `https://spdx.dev/Document`). Empty in sign-blob mode.
	PredicateURI string

	// SignedAt is when the signature completed. Useful for
	// audit logs.
	SignedAt time.Time
}

// Sentinel errors. The CLI branches on these so an operator who
// passed `--sign-with cosign-key` without installing Cosign sees
// a clear error message instead of a stack trace.
var (
	// ErrTooling — the underlying tool isn't installed or isn't
	// runnable. The CLI surfaces this as an exit-code 7
	// "tooling missing" with a recovery hint.
	ErrTooling = errors.New("sign: required tooling is not available")

	// ErrInvalidConfig — the caller's SignOptions is internally
	// inconsistent (e.g. ModeCosignKey without KeyPath, or
	// neither AttachToImage nor OutputFile). The CLI surfaces
	// this as exit-code 2 (invalid args) with the offending
	// field named.
	ErrInvalidConfig = errors.New("sign: invalid configuration")

	// ErrSigning — the underlying tool returned a non-zero exit
	// status. The wrapped error includes Cosign's stderr so
	// operators can debug without re-running.
	ErrSigning = errors.New("sign: signing failed")
)

// Validate reports the first ErrInvalidConfig-class problem with
// opts under mode. Centralised so the CLI flag-parser and the
// Signer's Sign() entry point share the same enforcement.
func (opts SignOptions) Validate(mode Mode) error {
	switch mode {
	case ModeNone:
		return nil
	case ModeCosignKey:
		if opts.KeyPath == "" {
			return errors.Join(ErrInvalidConfig,
				errors.New("--sign-with cosign-key requires --signing-key"))
		}
	case ModeCosignKeyless:
		// Cosign auto-detects the OIDC token from env at sign
		// time; we don't pre-validate the env vars here — Cosign's
		// error message is more informative than ours would be.
	default:
		return errors.Join(ErrInvalidConfig,
			errors.New("--sign-with: unknown mode"))
	}
	if opts.AttachToImage == "" && opts.OutputFile == "" {
		return errors.Join(ErrInvalidConfig,
			errors.New("either --attach-to-image or --signature-output is required"))
	}
	return nil
}
