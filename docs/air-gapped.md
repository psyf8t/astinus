# Air-gapped mode

Running Astinus on a host that can't reach the public internet —
the typical regulated-environment shape where container builds
happen behind a firewall, the runner pulls only from an internal
registry, and tools like `npm install` are blocked outright.

## What's bundled

These work without any network:

- The CPE bundled dictionary (~250 well-known PURL → CPE entries).
- The lifecycle / EOL snapshot (a small endoflife.date subset
  covering Node, Python, Go, Java, Debian, Ubuntu, Alpine, Postgres,
  MySQL, Redis, Kubernetes, Docker).
- The path-classification rules used by the Syft baseline filter
  and the untracked-component scanner.
- The compliance validators (NTIA, EU CRA Article 13).

What is NOT bundled (because it's data, not code):

- A complete CPE dictionary covering every published package.
- A full endoflife.date snapshot.
- Per-package metadata from npm / PyPI / Maven / Go module proxy
  — Astinus needs to call out for these.

The first two have offline workflows below. The third needs an
internal mirror — see [corporate.md](corporate.md).

## The flag set

```
--no-network              Refuse outbound network calls
--offline-db <path>       Path to a CPE / fingerprint catalogue
--lifecycle-snapshot <p>  Replace the bundled lifecycle data
--mirrors-config <path>   Internal package mirrors (npm/PyPI/Maven/...)
```

`--no-network` is the gate. With it set:

- Image must be local (`archive://`, `oci://`, `docker-daemon://`,
  `podman-daemon://`). Registry refs cause exit 30 with a clear
  message.
- The CPE resolver downgrades to `offline` regardless of
  `--cpe-mode`.
- The lifecycle resolver uses the snapshot only.
- The package-mirror enricher only fires if `--mirrors-config`
  points at an internal mirror — public registries are off limits.
- Cosign signing still works if your key material is local; for
  keyless signing you'd need `--rekor-url` / `--fulcio-url` /
  `--tuf-mirror` pointing at internal Sigstore endpoints.

## Workflow

### 1. Build the offline catalogue (one-time setup)

```bash
astinus offline-db build --output /shared/astinus-db
```

This creates the layout + a `manifest.json` header. The
`--include-*` flags that pull from public sources (NVD CPE
Dictionary, ClearlyDefined, popular-binaries hash list) are
recorded in the manifest but the data sourcing is still under
construction — operators currently populate the catalogue
manually:

```
<root>/
├── manifest.json
├── cpe/
│   ├── by-purl/<percent-encoded-purl>.json
│   └── by-name/<purl-type>/<lower-name>.json
└── fingerprint/
    └── <alg>/<digest>.json
```

Each file is one JSON object — see `astinus offline-db info
--path /shared/astinus-db` for the schema and stats.

### 2. Refresh the lifecycle snapshot (occasional)

On a host with internet access:

```bash
astinus lifecycle update --output /shared/astinus-lifecycle.json
```

Then ship the file to the air-gapped runner.

### 3. Configure your internal mirrors (one-time setup)

```yaml
# /etc/astinus/mirrors.yaml
version: 1
mirrors:
  - ecosystem: npm
    url: https://artifactory.corp.example/api/npm/npm-virtual
    mode: replace
    auth:
      type: bearer
      token_env: ARTIFACTORY_TOKEN

  - ecosystem: pypi
    url: https://artifactory.corp.example/api/pypi/pypi/simple
    mode: replace
    auth:
      type: basic
      username: ci-bot
      password_env: ARTIFACTORY_PASSWORD

  - ecosystem: maven
    url: https://artifactory.corp.example/maven-virtual
    mode: replace
```

`replace` mode is the safe default — Astinus never tries the
public upstream as a backup.

### 4. Generate the SBOM with your existing tool

```bash
syft archive:./myapp.tar -o cyclonedx-json > sbom.cdx.json
```

### 5. Enrich

```bash
astinus enrich \
  --sbom               sbom.cdx.json \
  --image              archive://./myapp.tar \
  --no-network \
  --offline-db         /shared/astinus-db \
  --lifecycle-snapshot /shared/astinus-lifecycle.json \
  --mirrors-config     /etc/astinus/mirrors.yaml \
  --output             enriched.cdx.json
```

If you accidentally pass a registry reference, Astinus exits
**30** and tells you to use `archive://` or `oci://`.

## Catalogue layout

```
/shared/astinus-db/
├── manifest.json
│
├── cpe/
│   ├── by-purl/
│   │   ├── pkg%3Anpm%2Flodash%404.17.20.json
│   │   └── pkg%3Apypi%2Fdjango%403.2.json
│   └── by-name/
│       ├── npm/lodash.json
│       └── pypi/django.json
│
└── fingerprint/
    └── sha256/
        └── deadbeef….json
```

URL-percent-encoding the PURL keeps every file system happy
(no `:` / `/` / `@` / `+` issues on Windows or NTFS-mounted
shares).

`astinus offline-db info --path /shared/astinus-db` prints the
manifest plus per-section file counts so you can sanity-check
after a refresh.

## What you gain (and what you lose)

You still get:

- Layer attribution.
- Base-image diff.
- Untracked-component detection (binaries / archives / scripts).
- Syft baseline noise filtering.
- CPE matching for everything in the bundled dictionary or your
  offline DB.
- Package metadata for everything your internal mirror has.
- Lifecycle / EOL data from the snapshot.
- Compliance findings (NTIA / EU CRA).
- Cosign signing if the key + Sigstore endpoints are local.

You lose:

- CPE matches for things not in the bundled dict or offline DB.
  Add them to the offline DB as you discover gaps.
- Package metadata for ecosystems not in your mirror config.
  Either extend the mirror or accept the gap.
- Lifecycle data for products not in the snapshot. Refresh more
  often.
- Public Sigstore (Rekor / Fulcio / TUF). Stand up an internal
  Sigstore deployment and point Astinus at it via
  `--rekor-url` / `--fulcio-url` / `--tuf-mirror`.

## Refresh cadence

A pragmatic rhythm:

| Asset | Refresh when |
|---|---|
| Offline CPE / fingerprint DB | Quarterly, or when a vulnerability scan misses something obvious. |
| Lifecycle snapshot | Monthly — endoflife.date changes incrementally. |
| Internal mirror | Whatever your existing Artifactory / Nexus replication schedule is. |
| Bundled dictionary in the binary | Whenever you upgrade Astinus. |

## Common failures

**`--no-network: image "..." requires a registry pull`** — the
image is a registry ref. Pull it into a local archive
(`docker save -o myapp.tar myapp:tag` then `--image
archive://./myapp.tar`) or use a local daemon scheme.

**Many components show up without licenses / homepage** — your
internal mirror doesn't have those packages. Either replicate
them, switch the mirror to `fallback` (only useful if the runner
can actually reach upstream), or live with the gap.

**Many components show up without CPEs** — they're not in the
bundled dictionary and not in your offline DB. Add them to the
offline DB or accept the gap; vulnerability matching for those
components won't work.

**`lifecycle.eol` log warnings for things you don't recognise**
— the snapshot might be stale, or you've added a runtime that
endoflife.date doesn't track. Refresh the snapshot or filter the
warning at the log level.
