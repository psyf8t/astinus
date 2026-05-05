# Signing SBOMs

Cosign-based signing for the SBOMs Astinus produces. Covers the
two modes (key-based, keyless), both output destinations
(detached signature, in-toto attestation on an OCI image), the
verification side, and the corporate-Sigstore knobs.

## Why this is its own subcommand

Astinus shells out to the `cosign` binary instead of importing
[sigstore-go](https://github.com/sigstore/sigstore-go). The
practical effect: you need cosign installed, but the Astinus
binary stays small (~12 MiB rather than ~60 MiB), and security
fixes in cosign reach you the moment you upgrade cosign — no
Astinus release required.

Install cosign first:

```bash
# macOS
brew install cosign

# Linux
curl -sSfL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 \
  -o /usr/local/bin/cosign && chmod +x /usr/local/bin/cosign
```

If cosign isn't on `$PATH`, point Astinus at it explicitly with
`--cosign-path /opt/cosign/bin/cosign`.

## Key-based signing

For private keys you control. Generate a pair once:

```bash
cosign generate-key-pair
# → cosign.key (private, encrypted with COSIGN_PASSWORD)
# → cosign.pub (public, ship this to verifiers)
```

Then sign the SBOM as part of the enrich step:

```bash
export COSIGN_PASSWORD="…"

astinus enrich \
  --sbom              sbom.cdx.json \
  --image             myapp:v1 \
  --output            sbom.cdx.json \
  --sign-with         cosign-key \
  --signing-key       cosign.key \
  --signature-output  sbom.sig
```

`COSIGN_PASSWORD` is cosign's own convention. If your CI uses a
different env var, point Astinus at it: `--signing-key-password-env
MY_COSIGN_PASS`.

The signature ends up at `sbom.sig`. Verify later:

```bash
astinus verify \
  --sbom       sbom.cdx.json \
  --signature  sbom.sig \
  --key        cosign.pub
```

Verification exit code is the verdict: `0` is good, anything else
is "do not trust this".

## Keyless signing

For CI environments where Sigstore can mint a short-lived
certificate from your OIDC identity (GitHub Actions, GitLab CI,
Buildkite, …):

```bash
astinus enrich \
  --sbom             sbom.cdx.json \
  --image            ghcr.io/org/myapp:v1 \
  --output           sbom.cdx.json \
  --sign-with        cosign-keyless \
  --attach-to-image  ghcr.io/org/myapp:v1
```

No `--signing-key`. Cosign auto-detects the OIDC token from
the CI environment, gets a short-lived cert from Fulcio, and
attaches the in-toto attestation to the OCI image — no separate
artefact to publish.

Verify keyless signatures by pinning the expected signer
identity:

```bash
astinus verify \
  --attached-to-image     ghcr.io/org/myapp:v1 \
  --cert-identity-regexp  '^https://github\.com/myorg/myrepo/.+@refs/heads/main$' \
  --cert-oidc-issuer      https://token.actions.githubusercontent.com
```

The regex protects against forks and PR builds — only the canonical
main-branch workflow can produce a valid signature.

## Output destinations

`--signature-output <path>` and `--attach-to-image <ref>` are
mutually exclusive. Pick one:

| Destination | When |
|---|---|
| `--signature-output sbom.sig` | You ship the SBOM as a separate artefact (release page, S3 bucket, …) and want a signature you can ship alongside. |
| `--attach-to-image ghcr.io/...:v1` | The SBOM travels with the image. Cosign writes an in-toto attestation to `<ref>:<digest>.sig` in the registry. Verifiers pull the image and the attestation lands automatically. |

For CycloneDX / SPDX attestations the predicate type URI is set
correctly (`https://cyclonedx.org/bom/v1.6` /
`https://spdx.dev/Document`), so consumers using the in-toto
spec recognise the format.

## Corporate Sigstore

Public Sigstore is convenient but air-gapped customers need a
self-hosted deployment of the Rekor transparency log + Fulcio
certificate authority + a TUF root mirror. Astinus passes these
through to cosign as env vars:

```bash
astinus enrich \
  --sign-with    cosign-keyless \
  --rekor-url    https://rekor.corp.example \
  --fulcio-url   https://fulcio.corp.example \
  --tuf-mirror   https://tuf.corp.example/repo \
  --ca-cert      /etc/ssl/corp-ca.pem \
  ...
```

These translate to `COSIGN_REKOR_URL` / `COSIGN_FULCIO_URL` /
`TUF_ROOT` / `SSL_CERT_FILE` — cosign's own env-var conventions.
The `--ca-cert` flag is shared with the image-pull path, so one
CA bundle covers both.

## Logging

The `sign.cosign.start` log line records the argv cosign was
invoked with. Sensitive flag values (`--key`, `--cert`,
`--token`, `--certificate`) are redacted to `<redacted>`. The
flag *name* stays visible so you can answer "did Astinus pass
`--key` correctly?" without exposing the file path.

## Failure handling

If signing fails, Astinus exits **50** (`ExitSigning`). The SBOM
file is already on disk — signing is a post-render step — so you
can re-run signing manually after fixing the issue:

```bash
cosign sign-blob --key cosign.key --output-signature sbom.sig sbom.cdx.json
```

Common failures:

**`sign: required tooling is not available: "cosign" not in
PATH`** — install cosign or set `--cosign-path`.

**`Error: incorrect password`** — `COSIGN_PASSWORD` is wrong or
unset. Set `--signing-key-password-env` to the right env var.

**`Error: signing ... HTTP 403`** — keyless signing's OIDC token
doesn't have permission to mint a Fulcio cert. Check your CI's
OIDC permissions (e.g. `id-token: write` on GitHub Actions).

**Verification: `cert subject does not match`** — the
`--cert-identity-regexp` doesn't match the actual signer. Check
the signer identity printed in cosign's output and tighten the
regex.

## Verification round-trip in CI

A pattern that catches signing pipeline regressions early:

```bash
# Sign as part of release
astinus enrich \
  --sbom sbom.cdx.json --image "$IMAGE" --output sbom.cdx.json \
  --sign-with cosign-key --signing-key cosign.key \
  --signature-output sbom.sig

# Immediately verify what we just produced
astinus verify --sbom sbom.cdx.json --signature sbom.sig --key cosign.pub
```

This costs ~3 seconds and proves the signature you're about to
publish is verifiable.

## What signing does NOT cover

- **Components.** Astinus signs the SBOM byte-for-byte. If you
  want signed provenance for each component, that's a separate
  per-component attestation workflow — out of scope here.
- **The container image.** Sign the image itself with `cosign
  sign $IMAGE` (or `cosign sign-blob` against an image archive).
  Astinus signs the SBOM, not the image.
- **A multi-format run.** If you produce both CycloneDX and SPDX
  in one Astinus invocation (via two runs with different
  `--output-format`s), sign each output separately.
