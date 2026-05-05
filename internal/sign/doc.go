// Package sign attaches Sigstore Cosign signatures and in-toto
// attestations to Astinus-emitted SBOMs.
//
// # Why subprocess, not Go library
//
// `github.com/sigstore/cosign/v2` would add ~50 MB of transitive
// dependencies (sigstore-go, transparency-log clients, crypto, …)
// to the Astinus binary — a 4× increase over today's ~12 MiB. The
// CI / CD environments that need signing (GitHub Actions, GitLab
// CI, Jenkins agents, corporate Tekton) all already have the
// `cosign` binary installed; bundling a second copy is waste.
//
// We wrap the subprocess instead. Astinus stays small. ADR-0036.
//
// # Capabilities
//
//   - Key-based signing (`cosign sign-blob --key`) producing a
//     detached signature file.
//   - Keyless signing (`cosign sign-blob --yes`) with the OIDC
//     token Cosign auto-detects from CI env (GITHUB_TOKEN, etc.).
//   - In-toto attestations attached to an OCI image (`cosign attest
//     --predicate <sbom> --type cyclonedx <image-ref>`).
//   - Corporate Sigstore endpoints — operators with private
//     Fulcio / Rekor / TUF instances pass the URLs via env
//     variables Cosign already understands.
//   - Sensitive-arg masking in log lines (key paths / tokens
//     never appear in `sign.cosign.start` events).
//
// # Pipeline placement
//
// Signing is a post-render step, not a pipeline enricher — the
// SBOM is signed AFTER it has been written to disk so the
// signature covers the final byte content. Wired in
// `internal/cli/enrich.go`'s `runEnrich` between the renderer
// and the compliance gate.
package sign
