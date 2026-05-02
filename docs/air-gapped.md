# Air-gapped Astinus

This guide covers running `astinus enrich` in environments with no
outbound network — the typical corporate-pipeline shape where
container builds happen behind a firewall and the only registry
accessible from the runner is an internal mirror (Artifactory,
Harbor, Nexus).

## Prerequisites

- Astinus binary in `$PATH`.
- Container image accessible without a public-internet pull
  (typically: pulled into your internal mirror or saved as a tar
  archive / OCI layout).
- (Optional) Offline catalogue directory built via
  `astinus offline-db build`.

## The flag set

Three CLI flags drive air-gapped operation:

```
--no-network                 Refuse outbound network calls
--offline-db <path>          Path to a catalogue built via offline-db build
--config <path>              YAML with per-registry config (mTLS, auth, proxy)
```

## Workflow

### 1. Build the offline catalogue (once per refresh cycle)

```bash
astinus offline-db build \
  --output /shared/nfs/astinus-db \
  --include-nvd-cpe \
  --include-clearlydefined \
  --include-popular-binaries \
  --notes "monthly refresh — ticket OPS-1234"
```

In Stage 12 the `--include-*` flags are accepted and recorded in
`manifest.json`, but the actual data sourcing lands in Stage 13.
Until then operators populate the catalogue manually:

- **CPE entries by PURL**:
  `<root>/cpe/by-purl/<percent-encoded-purl>.json`
- **CPE entries by (type, name)**:
  `<root>/cpe/by-name/<type>/<lower-name>.json`
- **Fingerprint entries**:
  `<root>/fingerprint/<alg>/<digest>.json`

Each file is one JSON object — see `manifest.json` for schema
hints and `astinus offline-db info --path <root>` to inspect the
catalogue.

### 2. Generate the SBOM with your existing tool

```bash
syft myapp.tar -o cyclonedx-json > sbom.cdx.json
```

### 3. Enrich with no-network + offline catalogue

```bash
astinus enrich \
  --sbom        sbom.cdx.json \
  --image       archive://./myapp.tar \
  --no-network \
  --offline-db  /shared/nfs/astinus-db \
  --output      enriched.cdx.json
```

If you accidentally pass a registry reference with `--no-network`,
Astinus exits with code **30** and a clear message
(`--no-network: image %q requires a registry pull`).

## Catalogue layout reference

```
<root>/
  manifest.json
  cpe/
    by-purl/
      pkg%3Anpm%2Fexpress%404.18.2.json
    by-name/
      npm/
        express.json
      pypi/
        django.json
  fingerprint/
    sha256/
      abc1234567890.json
```

### `manifest.json`

```json
{
  "version":  1,
  "built_at": "2026-05-02T04:22:00Z",
  "built_by": "astinus-v0.0.0-dev",
  "sources":  ["nvd-cpe", "clearlydefined"],
  "notes":    "monthly refresh — ticket OPS-1234"
}
```

### CPE entry (by-purl OR by-name)

```json
{
  "vendor":  "expressjs",
  "product": "express",
  "source":  "nvd-cpe"
}
```

The catalogue records vendor + product; the resolver builds the
full `cpe:2.3:a:vendor:product:<version>:*:*:*:*:*:*:*` URI at
lookup time using the version from the input PURL.

### Fingerprint entry

```json
{
  "name":     "jq",
  "version":  "1.7.1",
  "purl":     "pkg:generic/jq@1.7.1",
  "cpes":     ["cpe:2.3:a:jqlang:jq:1.7.1:*:*:*:*:*:*:*"],
  "licenses": [{"expression": "MIT"}],
  "source":   "popular-binaries"
}
```

## Per-registry config still applies

`--no-network` does NOT block per-registry mTLS / proxy / Artifactory
auth. If your runner can reach `artifactory.corp.com` over HTTPS but
nowhere else, `astinus.yaml` from Stage 10 still works:

```yaml
registries:
  - host: artifactory.corp.com
    auth:
      type: artifactory-token
      token-env: ARTIFACTORY_TOKEN
    tls:
      ca-cert: /etc/ssl/corp-ca.pem
```

Combined invocation:

```bash
astinus enrich \
  --sbom        sbom.cdx.json \
  --image       artifactory.corp.com/team/app:v1 \
  --config      /etc/astinus/corp.yaml \
  --offline-db  /shared/nfs/astinus-db \
  --output      enriched.cdx.json
```

Note: `--no-network` is omitted here because Artifactory IS the
network — air-gapped from the public internet, but reachable from
the runner.

## Exit codes (recap)

| Code | Meaning |
|---|---|
| 0  | Success |
| 3  | SBOM read/parse error |
| 4  | Image open / pull error |
| 5  | Enricher returned error |
| 6  | Output write error |
| 30 | `--no-network` set, but the run requires a registry pull |

## Roadmap

Stage 13 will populate `--include-*` so a single
`astinus offline-db build` command produces a fully-loaded
catalogue without manual file authoring.
