# Quickstart

Get from "I have an SBOM" to "I have an enriched SBOM" in five minutes.

## Install

Build from source — there are no published binaries yet:

```bash
git clone https://github.com/psyf8t/astinus.git
cd astinus
make build
# binary lands at ./bin/astinus
```

If you'd rather not put it on your `$PATH`, every command below
works with `./bin/astinus` instead of `astinus`.

You also need a primary SBOM generator. The examples use
[Syft](https://github.com/anchore/syft):

```bash
# macOS
brew install syft

# everything else
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh
```

## Your first enrichment

```bash
syft alpine:3.19 -o cyclonedx-json > sbom.cdx.json

astinus enrich \
  --sbom   sbom.cdx.json \
  --image  alpine:3.19 \
  --output enriched.cdx.json
```

That's it. `enriched.cdx.json` now has:

- Per-component layer attribution (which `RUN`/`COPY`/`ADD` line
  introduced each package).
- Base-image diff (which components are inherited from upstream
  vs. what your team added).
- CPE identifiers wherever Astinus could resolve one — this is
  what makes Grype / OSV / Trivy actually find CVEs.
- License / homepage / repository pulled from the package
  registry (npm, PyPI, Maven, Go module proxy).
- Lifecycle / EOL annotations for runtimes and OS images.
- A compliance summary: counts of NTIA / EU CRA findings.

Diff `sbom.cdx.json` against `enriched.cdx.json` to see what
landed.

## CI pipeline

```bash
# Fail the build if the enriched SBOM has any high-severity
# compliance findings.
syft "$IMAGE" -o cyclonedx-json | astinus enrich \
  --sbom    - \
  --image   "$IMAGE" \
  --fail-on high \
  --output  enriched.cdx.json
```

Exit codes you can branch on in CI:

| Code | Meaning |
|---|---|
| 0 | Success. |
| 4 | Image-load failure (registry pull / archive read). |
| 30 | `--no-network` set but the image needs a registry call. |
| 40 | `--fail-on` triggered — compliance findings at or above the chosen severity. |
| 50 | Signing failed (cosign missing, key wrong, signature step errored). |

## Behind a corporate registry

```bash
astinus enrich \
  --sbom   sbom.cdx.json \
  --image  artifactory.corp.example/team/myapp:v1.2.3 \
  --output enriched.cdx.json
```

`docker login` is enough for most setups. If your registry needs
mTLS, a custom CA, or a specific proxy, see
[corporate.md](corporate.md).

## Air-gapped

```bash
astinus enrich \
  --sbom        sbom.cdx.json \
  --image       archive://./myapp.tar \
  --no-network \
  --offline-db  /shared/astinus-db \
  --output      enriched.cdx.json
```

The CPE dictionary, lifecycle snapshot, and registry stubs are
embedded in the binary; with `--no-network` Astinus never reaches
out. Full guide in [air-gapped.md](air-gapped.md).

## Sign the SBOM

You'll need [cosign](https://docs.sigstore.dev/cosign/installation/)
on `$PATH`.

```bash
cosign generate-key-pair  # one time

astinus enrich \
  --sbom              sbom.cdx.json \
  --image             myapp:v1 \
  --output            sbom.cdx.json \
  --sign-with         cosign-key \
  --signing-key       cosign.key \
  --signature-output  sbom.sig
```

Verify later with `astinus verify --sbom sbom.cdx.json
--signature sbom.sig --key cosign.pub`. Full signing workflow in
[signing.md](signing.md).

## Where to next

- [configuration.md](configuration.md) — every flag, what it
  does, when you'd want it.
- [corporate.md](corporate.md) — Artifactory / Harbor / Nexus
  mirrors, mTLS, proxy, auth.
- [air-gapped.md](air-gapped.md) — running with no outbound
  network.
- [signing.md](signing.md) — cosign sign + verify roundtrip,
  in-toto attestations.
- [compliance.md](compliance.md) — `--fail-on`, severity
  tuning, NTIA / EU CRA validators.
