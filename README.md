# Astinus

> *Master Historian of Krynn — chronicler of every component your scanners missed.*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.25%2B-00ADD8.svg)](https://go.dev/)
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX%20%7C%20SPDX-success.svg)](#)

**Astinus** is an SBOM enricher for Docker and OCI container images. It doesn't generate SBOMs from scratch — it takes the output of an existing tool (Syft, Trivy, cdxgen, Microsoft sbom-tool, …) and fills in the gaps those tools leave behind: layer attribution, base-image diff, untracked components, real CPE identifiers, package metadata, lifecycle / EOL data, and Cosign signatures.

```bash
syft myapp:v1 -o cyclonedx-json | astinus enrich \
  --sbom -          \
  --image  myapp:v1 \
  --output enriched.cdx.json
```

Five-minute walkthrough: [docs/quickstart.md](docs/quickstart.md).

## Why bother

The current generation of SBOM tools is good at one thing — extracting components from package managers (`dpkg`, `apk`, `pip`, `npm`, `gem`, …). Run Syft on `nginx:latest` and you get a solid inventory of what `apt` and friends know about.

But containers don't only contain package-managed software. They also contain:

- Vendored binaries copied in via `COPY` / `ADD`
- Statically-linked Go and Rust binaries with embedded module info
- JARs, WARs, and other archives dropped into application directories
- Scripts and tools pulled from `curl | sh` or GitHub releases
- Files inherited from the base image that get attributed to your team's supply chain even though they're not your responsibility

These are the things your SBOM tool silently skips. Vulnerabilities in them won't show up in your scanner. Compliance reports based on these SBOMs are incomplete by design.

Astinus reads what your scanners wrote and writes what they missed.

## What it adds

| | Syft alone | Syft + Astinus |
|---|:---:|:---:|
| Package-managed components (apt, apk, npm, …) | ✅ | ✅ |
| Vendored binaries (Go, Rust, static libs) | partial | ✅ |
| Embedded archives (JARs in WARs, etc.) | partial | ✅ |
| Layer attribution per component | ❌ | ✅ |
| Base image / application split | ❌ | ✅ |
| Auto base-image detection from labels | ❌ | ✅ |
| Reliable CPE for NVD vulnerability matching | partial | ✅ |
| Provenance per component (which `RUN` / `COPY`) | ❌ | ✅ |
| License / homepage / repository from package registries | ❌ | ✅ |
| Lifecycle / EOL annotations for runtimes and OS | ❌ | ✅ |
| NTIA + EU CRA compliance findings + `--fail-on` gate | ❌ | ✅ |
| Cosign signing + in-toto attestations | ❌ | ✅ |

## Built for CI/CD

- Single static binary (`CGO_ENABLED=0`), no runtime dependencies. ~12 MiB.
- Stdin/stdout pipe-friendly for streamed pipelines.
- Semantic exit codes: 30 for `--no-network` violation, 40 for `--fail-on` trip, 50 for signing failure.
- Structured JSON logs auto-detected in CI environments.
- Stable, deterministic output for diffing across runs.
- First-class corporate registry support — JFrog Artifactory, Harbor, Nexus, ECR, GCR, ACR, GHCR.
- mTLS, custom CA bundles, HTTP proxy out of the box.
- Air-gapped mode with bundled offline catalogues for CPE and lifecycle data.

## What it is NOT

- **Not a replacement for Syft / Trivy / cdxgen.** It runs *after* them, on their output.
- **Not a vulnerability scanner.** Pair it with Grype, OSV-Scanner, or your existing tooling. Astinus's job is to make sure those scanners have the CPEs / PURLs they need.
- **Not an SBOM management platform.** Use it with [Dependency-Track](https://dependencytrack.org/), [GUAC](https://guac.sh/), or whatever you already have.

## How it works

```
┌──────────────┐     ┌──────────────┐     ┌──────────────────────┐
│  Your SBOM   │     │  Your Image  │     │  Optional Base Image │
│  (CDX/SPDX)  │     │  (any source)│     │  (auto or explicit)  │
└──────┬───────┘     └──────┬───────┘     └──────────┬───────────┘
       │                    │                        │
       └────────────────────┼────────────────────────┘
                            ▼
              ┌──────────────────────────┐
              │   Canonical SBOM model   │
              └────────────┬─────────────┘
                           ▼
        ┌──────────────────────────────────────┐
        │       Enrichment pipeline            │
        │  ┌────────────────────────────────┐  │
        │  │ Syft baseline noise filter     │  │
        │  │ Layer attribution              │  │
        │  │ Base image diff                │  │
        │  │ Untracked detection            │  │
        │  │ CPE enrichment                 │  │
        │  │ Package-registry metadata      │  │
        │  │ Lifecycle / EOL                │  │
        │  │ Compliance validators          │  │
        │  │ <your custom enricher>         │  │
        │  └────────────────────────────────┘  │
        └──────────────────┬───────────────────┘
                           ▼
              ┌──────────────────────────┐
              │  Enriched SBOM           │
              │  (CDX, SPDX, SARIF,      │
              │   summary report)        │
              │  + optional cosign sig   │
              └──────────────────────────┘
```

The pipeline is built around small, composable enrichers. Each enricher reads from and writes to a canonical internal SBOM model, which means new enrichers can be added without touching the core. Order is computed by a topological sort on declared dependencies and logged at startup as `pipeline.order`.

## Documentation

- [Quickstart](docs/quickstart.md) — install + first enrich command
- [Configuration reference](docs/configuration.md) — every flag, every YAML key, exit codes
- [Corporate environments](docs/corporate.md) — Artifactory / Harbor / Nexus, mTLS, proxy, auth
- [Air-gapped mode](docs/air-gapped.md) — `--no-network`, offline catalogue layout
- [SBOM signing](docs/signing.md) — cosign sign + verify, in-toto attestations
- [Compliance gate](docs/compliance.md) — `--fail-on`, NTIA / EU CRA validators, severity overrides

Architecture decisions are recorded under [docs/adr/](docs/adr/) — one file per material decision.

## Extensibility

Astinus is designed to be extended without forking. The following extension points are first-class:

| Type | Interface | Use case |
|---|---|---|
| Enricher | `enrich.Enricher` | New sources of SBOM enrichment (e.g., internal license database) |
| Validator | `policy.Validator` | Compliance checks beyond the bundled NTIA / EU CRA rules |
| Image source | `image.source.ImageSource` | Custom image storage backends |
| Auth provider | `image.auth.CredentialProvider` | Corporate authentication systems |
| Output renderer | `output.Renderer` | Internal report formats |
| Fingerprint matcher | `fingerprint.matcher.Matcher` | Internal binary catalogues |
| Package source | `enrich.registry.Source` | New ecosystems (e.g. RubyGems, Conan, …) |

Custom builds are assembled by importing additional packages — no plugin system, no runtime overhead, no ABI compatibility headaches.

## The name

In the [Dragonlance](https://dragonlance.fandom.com/wiki/Astinus_of_Palanthas) setting, **Astinus of Palanthas** is the immortal Master Historian of Krynn. From the Great Library of Palanthas, he and his Order of Aesthetics continuously record every event in the world — meticulously, completely, without interpretation. The Chronicles of Krynn are never finished; they are always being added to.

Your SBOM is a chronicle of what's inside your container. Existing tools draft it; Astinus continuously fills in what was missed.

## Contributing

The most useful contributions right now:

- **Issues**: edge cases you'd want covered, gaps in coverage, ideas for new enrichers.
- **Real-world SBOMs and images** that demonstrate gaps Astinus should close.
- **Naming things**: if you spot a clearer term in the docs, suggest it.

A formal contribution guide will land with v1.0.

## License

Astinus is released under the [Apache License 2.0](LICENSE).

## Acknowledgements

Astinus stands on the shoulders of the open-source SBOM community:

- [Anchore Syft](https://github.com/anchore/syft) — the SBOM generator Astinus is designed to enrich
- [CycloneDX](https://cyclonedx.org/) and [SPDX](https://spdx.dev/) — the standards we read and write
- [google/go-containerregistry](https://github.com/google/go-containerregistry) — the image abstraction we build on
- [Sigstore Cosign](https://docs.sigstore.dev/cosign/overview) — the signing toolchain we wrap
- [endoflife.date](https://endoflife.date) — the lifecycle / EOL data source
- [ClearlyDefined](https://clearlydefined.io/) and [Software Heritage](https://www.softwareheritage.org/) — the catalogues we look up against
