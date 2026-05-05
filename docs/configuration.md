# Configuration

Astinus is driven by command-line flags and (optionally) two YAML
files: an image-registry config (`--config`) and a package-mirror
config (`--mirrors-config`). Everything has a sensible default, so
the minimal invocation is just `--sbom` + `--image` + `--output`.

This page is the reference. For task-flavoured walkthroughs, see
the other docs in this folder.

## Inputs and outputs

| Flag | What |
|---|---|
| `--sbom <path>` | Input SBOM. CycloneDX 1.6 (JSON or XML) or SPDX 2.3 (JSON or tag-value). `-` reads from stdin. |
| `--image <ref>` | Container image to enrich against. Accepts a registry ref (`alpine:3.19`, `ghcr.io/org/img:tag`), `archive://./img.tar`, `oci://./layout-dir`, `docker-daemon://name:tag`, `podman-daemon://name:tag`. |
| `--output <path>` | Where the enriched SBOM lands. `-` writes to stdout. |
| `--output-format` | `same` (default — match the input), `cyclonedx-json`, `cyclonedx-xml`, `spdx-json`, `spdx-tag-value`, `sarif`, `summary`. |
| `--platform linux/arm64` | Pick one platform from a multi-arch index. |

## Enricher selection

Each enricher fills a specific gap. They run in topological order
based on declared dependencies; the order is logged at startup
(`pipeline.order`).

| Default | Disable with | What it adds |
|---|---|---|
| layer attribution | `--disable layer` | which layer / Dockerfile line introduced each component |
| base-image diff | `--disable basediff` | `base` / `app` / `unknown` split |
| untracked-component scan | `--disable untracked` | binaries / archives / scripts not in any package manager |
| Syft baseline prefilter | `--no-syft-prefilter` | drops the `/etc/cron.d/` / `/etc/pam.d/` noise rows |
| CPE enrichment | `--disable cpe` | resolves PURL → CPE so NVD-based scanners actually match |
| package-registry metadata | `--no-registry` | license / homepage / repository from npm / PyPI / Maven / Go |
| lifecycle / EOL | `--no-lifecycle` | `astinus:lifecycle:status=eol\|maintenance\|active` |
| compliance | `--disable compliance` | NTIA + EU CRA finding counts |
| dedup | `--disable dedup` | merges duplicate component rows |

You can also pick a positive set with `--enable a,b,c`. Passing
both takes the intersection.

## Networking and TLS

Defaults are paranoid-by-default for outbound; relaxed for the
image registry only when you explicitly say so.

| Flag | What |
|---|---|
| `--no-network` | Refuse all outbound calls. Image must be local (archive / OCI layout / daemon). Exit 30 if the image needs a registry pull. |
| `--ca-cert <path>` | Add a custom CA bundle on top of the system roots. Used by image pull, registry-metadata fetch, and (via `SSL_CERT_FILE`) cosign. |
| `--insecure` | Allow plaintext HTTP to the image registry. |
| `--skip-tls-verify` | Don't validate the registry TLS certificate. Avoid. |
| `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` | Standard env-var proxy config — Astinus uses `http.ProxyFromEnvironment`. |

## CPE matching

CPEs drive vulnerability matching. By default Astinus uses a
hybrid resolver: bundled dictionary first, then the NVD API for
the misses.

| Flag | What |
|---|---|
| `--cpe-mode online\|offline\|hybrid` | Default hybrid. `--no-network` forces offline. |
| `--nvd-api-key <key>` | Sets the NVD rate limit to 50 requests / 30s instead of 5. Reads `NVD_API_KEY` if the flag is empty. |
| `--include-rejected-cpe` | Emit `astinus:cpe:rejected:N` properties for diagnostics. Off by default — rejected candidates always show up in the `cpe.rejected` debug log. |

## Package-registry metadata (`--mirrors-config`)

Astinus fetches license / homepage / repository / hashes from the
public package registries (npm, PyPI, Maven, Go module proxy).
For corporate environments, point it at your internal mirror via
a YAML config:

```yaml
# mirrors.yaml
version: 1
mirrors:
  - ecosystem: npm
    url: https://artifactory.corp.example/api/npm/npm-virtual
    mode: replace                        # see "Mirror modes" below
    auth:
      type: bearer
      token_env: ARTIFACTORY_TOKEN       # never put secrets in the file
    tls:
      ca_cert: /etc/ssl/corp-ca.pem
      client_cert: /etc/ssl/client.pem   # optional mTLS
      client_key:  /etc/ssl/client.key

  - ecosystem: pypi
    url: https://artifactory.corp.example/api/pypi/pypi/simple
    mode: replace
    auth:
      type: basic
      username: ci-bot
      password_env: ARTIFACTORY_PASSWORD
```

Then:

```bash
astinus enrich --mirrors-config mirrors.yaml ...
```

### Mirror modes

| Mode | Behaviour |
|---|---|
| `replace` (default) | Use only this mirror. Never call upstream — even on 404. The right choice for air-gapped environments. |
| `fallback` | Try this mirror first; on 404 or transient error, fall back to the public upstream. The right choice when you want corporate caching but tolerate gaps. |

Multiple entries for one ecosystem are tried in declaration order,
with all `replace` entries before any `fallback` entries.

### Auth shapes

```yaml
# Bearer
auth:
  type: bearer
  token_env: ARTIFACTORY_TOKEN

# Basic
auth:
  type: basic
  username: ci-bot
  password_env: ARTIFACTORY_PASSWORD

# Custom header (JFrog API key, GHCR token, etc.)
auth:
  type: header
  header_name: X-JFrog-Art-Api
  header_value_env: ARTIFACTORY_API_KEY
```

Token / password values can be inlined (`token:`, `password:`),
but `*_env` is strongly preferred — secrets stay out of YAML.

### Caching

| Flag | What |
|---|---|
| `--registry-cache-dir <dir>` | Persist the metadata cache across runs. Default: in-memory only. |
| `--registry-cache-ttl <duration>` | Per-entry TTL. Default 168h (7 days) — published packages rarely change. `0` disables expiry. |

### Disabling

`--no-registry` skips this enricher entirely. Useful when your
mirror is down and you'd rather ship an SBOM without the metadata
than fail the build.

## Lifecycle / EOL data

The lifecycle enricher annotates OS and runtime components
(Node, Python, Go, Java, Debian, Ubuntu, Alpine, Postgres, MySQL,
Redis, Kubernetes, Docker, …) with active-support and end-of-life
dates from [endoflife.date](https://endoflife.date).

A small snapshot is embedded in the binary so air-gapped operators
get baseline coverage. To refresh:

```bash
astinus lifecycle update --output ~/.cache/astinus/lifecycle/snapshot.json
astinus enrich \
  --lifecycle-snapshot ~/.cache/astinus/lifecycle/snapshot.json \
  ...
```

| Flag | What |
|---|---|
| `--no-lifecycle` | Disable. |
| `--lifecycle-mode online\|offline\|hybrid` | Default hybrid. Online → endoflife.date first, snapshot fallback; offline → snapshot only. `--no-network` overrides to offline. |
| `--lifecycle-snapshot <path>` | Use this snapshot instead of the embedded seed. |

The properties stamped on each matching component:

```
astinus:lifecycle:product            nodejs
astinus:lifecycle:cycle              20
astinus:lifecycle:release-date       2023-04-18
astinus:lifecycle:active-support-end 2024-10-22
astinus:lifecycle:eol                2026-04-30
astinus:lifecycle:lts                true
astinus:lifecycle:status             active | maintenance | eol
astinus:lifecycle:days-until-eol     365
astinus:lifecycle:source             endoflife.date | bundled
```

## Compliance gate (`--fail-on`)

```bash
astinus enrich --fail-on high ...
```

Exits 40 when any compliance finding lands at or above the named
severity. Severities, low to high: `info`, `low`, `medium`,
`high`, `critical`.

The bundled severity policy has per-ecosystem rules — for example,
NTIA-MISSING-SUPPLIER is `info` for npm packages (everyone leaves
it blank) but `high` for application binaries. Override via
`--compliance-config <yaml>`.

The full compliance walkthrough — what each rule checks, how to
write an override, how to read the SARIF output — lives in
[compliance.md](compliance.md).

## Signing

```bash
astinus enrich \
  --sign-with         cosign-key \
  --signing-key       cosign.key \
  --signature-output  sbom.sig \
  ...
```

| Flag | What |
|---|---|
| `--sign-with cosign-key\|cosign-keyless` | Empty (default) disables signing. Wraps the cosign subprocess — install it separately. |
| `--signing-key <path>` | Cosign private key (cosign-key mode). |
| `--signing-key-password-env <var>` | Env var with the key passphrase. Default `COSIGN_PASSWORD` (cosign's own convention). |
| `--signature-output <path>` | Detached signature. Required unless `--attach-to-image` is set. |
| `--attach-to-image <ref>` | Push the in-toto attestation to an OCI image instead of writing a file. |
| `--rekor-url` / `--fulcio-url` / `--tuf-mirror` | Corporate Sigstore endpoints. Translated to `COSIGN_REKOR_URL` / `COSIGN_FULCIO_URL` / `TUF_ROOT`. |
| `--cosign-path <path>` | Override `$PATH` lookup. |

Full workflow + verification in [signing.md](signing.md).

## Image-registry config (`--config`)

Different concern from `--mirrors-config`. `--config` controls how
Astinus pulls the **container image** itself — per-host auth, mTLS,
proxy. The schema:

```yaml
# astinus.yaml
registries:
  - host: artifactory.corp.example
    auth:
      provider: artifactory
      mode: token                        # token | apikey | oidc
      token_env: ARTIFACTORY_TOKEN
    tls:
      ca_cert: /etc/ssl/corp-ca.pem
      client_cert: /etc/ssl/client.pem
      client_key:  /etc/ssl/client.key
    proxy: http://proxy.corp.example:3128
    insecure: false
```

For most setups `docker login` (which writes
`~/.docker/config.json`) is enough — Astinus reads it
automatically.

## Air-gapped catalogue

The CPE / fingerprint catalogue lives separately from the package
mirrors. Build it with:

```bash
astinus offline-db build --output /shared/astinus-db
```

…then reference it on every run:

```bash
astinus enrich --no-network --offline-db /shared/astinus-db ...
```

Catalogue layout and refresh workflow in [air-gapped.md](air-gapped.md).

## Logging and observability

| Flag | Default | What |
|---|---|---|
| `--log-level` | `info` | `debug`, `info`, `warn`, `error`. |
| `--log-format` | `auto` | `text`, `json`, `auto` (json under CI, text on a TTY). |
| `--quiet` | off | Errors only on stderr. |
| `--metrics-output <dest>` | off | Emit Prometheus text-format metrics. `stdout`, `stderr`, or `file:/path`. |
| `--tracing-endpoint <url>` | off | OpenTelemetry collector endpoint (OTLP HTTP). |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Generic / unexpected error. |
| 2 | Bad CLI arguments. |
| 3 | SBOM read / parse failure. |
| 4 | Image load failure (registry pull, archive read, daemon). |
| 5 | Enricher pipeline error (e.g. unknown enricher in `--enable`). |
| 6 | Output write failure. |
| 30 | `--no-network` set but the image needs a registry call. |
| 40 | `--fail-on` triggered. |
| 50 | Signing step failed (cosign missing, signature error). |
