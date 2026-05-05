package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/psyf8t/astinus/internal/sign"
)

// verifyOptions are bound to the `astinus verify` flags.
type verifyOptions struct {
	sbom               string
	signature          string
	attachedToImage    string
	keyPath            string
	certIdentityRegexp string
	certOIDCIssuer     string
	rekorURL           string
	fulcioURL          string
	tufMirror          string
	caBundle           string
	cosignPath         string
}

// newVerifyCommand returns the `astinus verify` command — wraps
// `cosign verify-blob` (detached) and `cosign verify-attestation`
// (image-attached). Two auth flavours: key-based (`--key`) and
// keyless (`--cert-identity-regexp` + `--cert-oidc-issuer`).
//
// Same corporate Sigstore overrides as `astinus enrich --sign-with`
// so operators reuse the same flag set for sign + verify.
func newVerifyCommand() *cobra.Command {
	opts := &verifyOptions{}
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a Cosign signature or in-toto attestation on an SBOM",
		Long: `Wraps cosign verify-blob (detached signatures) and
cosign verify-attestation (signatures attached to an OCI image).

Two flavours:

  --signature <path> --sbom <path> --key <pub.key>
    Detached signature verification.

  --attached-to-image <ref> --cert-identity-regexp <regex> \
                            --cert-oidc-issuer <url>
    In-toto attestation pulled from the OCI registry, scoped to a
    specific OIDC identity (keyless verification).

Corporate Sigstore endpoints (--rekor-url / --fulcio-url /
--tuf-mirror / --ca-cert) work the same way as on the enrich
command's --sign-with path.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runVerify(c.Context(), c.OutOrStdout(), opts)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.sbom, "sbom", "", "Path to the SBOM being verified (required for detached mode)")
	flags.StringVar(&opts.signature, "signature", "", "Detached signature blob path")
	flags.StringVar(&opts.attachedToImage, "attached-to-image", "",
		"OCI image reference Cosign reads the attestation back from")
	flags.StringVar(&opts.keyPath, "key", "", "Public key path (key-based verification)")
	flags.StringVar(&opts.certIdentityRegexp, "cert-identity-regexp", "",
		"Regex constraint for the signing OIDC identity (keyless verification)")
	flags.StringVar(&opts.certOIDCIssuer, "cert-oidc-issuer", "",
		"OIDC issuer URL for keyless verification (e.g. https://token.actions.githubusercontent.com)")
	flags.StringVar(&opts.rekorURL, "rekor-url", "",
		"Corporate Rekor transparency-log URL. Empty = Sigstore public.")
	flags.StringVar(&opts.fulcioURL, "fulcio-url", "",
		"Corporate Fulcio CA URL. Empty = Sigstore public.")
	flags.StringVar(&opts.tufMirror, "tuf-mirror", "",
		"TUF root mirror URL for air-gapped Sigstore.")
	flags.StringVar(&opts.caBundle, "ca-cert", "",
		"Corporate CA PEM bundle (passed to cosign via SSL_CERT_FILE).")
	flags.StringVar(&opts.cosignPath, "cosign-path", "",
		"Override the cosign binary lookup (default: PATH).")
	return cmd
}

func runVerify(ctx context.Context, out io.Writer, opts *verifyOptions) error {
	verifier, err := sign.NewVerifier(sign.CosignOptions{
		CosignPath: opts.cosignPath,
		Logger:     LoggerFrom(ctx),
	})
	if err != nil {
		return newExitError(ExitSigning, err)
	}
	verifyOpts := sign.VerifyOptions{
		SBOMPath:           opts.sbom,
		SignaturePath:      opts.signature,
		AttachedToImage:    opts.attachedToImage,
		KeyPath:            opts.keyPath,
		CertIdentityRegexp: opts.certIdentityRegexp,
		CertOIDCIssuer:     opts.certOIDCIssuer,
		RekorURL:           opts.rekorURL,
		FulcioURL:          opts.fulcioURL,
		TUFMirror:          opts.tufMirror,
		CABundle:           opts.caBundle,
	}
	result, err := verifier.Verify(ctx, verifyOpts)
	if err != nil {
		return newExitError(ExitSigning, err)
	}
	fmt.Fprintf(out, "verified: %s\n", result.VerifiedAt.Format("2006-01-02T15:04:05Z07:00"))
	if len(result.Stdout) > 0 {
		_, _ = out.Write(result.Stdout)
	}
	return nil
}
