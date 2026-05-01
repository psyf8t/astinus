# Astinus
 
> *Master Historian of Krynn — chronicler of every component your scanners missed.*
 
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.22%2B-00ADD8.svg)](https://go.dev/)
[![Status](https://img.shields.io/badge/status-pre--MVP-orange.svg)](#roadmap)
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX%20%7C%20SPDX-success.svg)](#)
 
**Astinus** is an open-source **SBOM enricher** for Docker and OCI container images. It does not generate SBOMs from scratch — instead, it takes the output of existing tools (Syft, Trivy, cdxgen, Microsoft sbom-tool, …) and **fills the gaps they leave behind**.
 
---
 
> ⚠️ **Status: Pre-MVP / Early Development**
>
> The specification is finalized, but no functional code has shipped yet. Architecture, CLI surface, and output formats are subject to change. Star the repo to follow progress, or check the [Roadmap](#roadmap).
 
---
 
## Why Astinus?
 
The current generation of SBOM tools is great at one thing — extracting components from package managers (`dpkg`, `apk`, `pip`, `npm`, `gem`, ...). Run Syft on `nginx:latest` and you get a solid inventory of what `apt` and friends know about.
 
But containers don't only contain package-managed software. They also contain:
 
- **Vendored binaries** copied in via `COPY` or `ADD`
- **Statically-linked Go and Rust binaries** with embedded module info
- **JARs, WARs, and other archives** dropped into application directories
- **Scripts and tools** pulled from `curl | sh` or GitHub releases
- **Files inherited from the base image** that get attributed to your team's supply chain even though they're not your responsibility
These are the things your SBOM tool **silently skips**. Vulnerabilities in them won't show up in your scanner. Compliance reports based on these SBOMs are incomplete by design.
 
Astinus reads what your scanners wrote, and writes what they missed.
 
## What Astinus Adds
 
| Feature | What it does |
|---|---|
| **Untracked components** | Finds and identifies binaries, archives, and embedded artifacts that aren't tracked by any package manager. Uses fingerprinting (Go `buildinfo`, JAR `MANIFEST.MF`, hash lookups in ClearlyDefined and Software Heritage) to identify what they are. |
| **Layer attribution** | For every component, records which image layer introduced it and which Dockerfile instruction (`RUN`, `COPY`, `ADD`) added it. |
| **Base image diff** | Splits components into `base` / `application` / `unknown` so you see exactly what your team added on top of upstream. Auto-detects the base image from OCI labels when possible. |
| **CPE enrichment** | Generates reliable [CPE 2.3](https://nvd.nist.gov/products/cpe) identifiers for components that have a PURL but no CPE — fixing one of the most common reasons NVD-based vulnerability matching produces false negatives. |
| **Format-agnostic** | Reads and writes CycloneDX (1.6) and SPDX (2.3+). Round-trip safe for CycloneDX. |
 
## What Astinus is NOT
 
- **Not a replacement for Syft / Trivy / cdxgen.** It runs *after* them, on their output.
- **Not a vulnerability scanner.** Pair it with Grype, OSV-Scanner, or your existing tooling.
- **Not a SBOM management platform.** Use it with [Dependency-Track](https://dependencytrack.org/), [GUAC](https://guac.sh/), or whatever you already have.
## Quickstart (planned)
 
> The commands below describe the intended UX. They will work as soon as the MVP ships. Until then they are spec, not docs.
 
Basic enrichment:
 
```bash
syft myapp:v1 -o cyclonedx-json > sbom.cdx.json
 
astinus enrich \
  --sbom sbom.cdx.json \
  --image myapp:v1 \
  --output enriched.cdx.json
```
 
Pipe-friendly for CI:
 
```bash
syft $IMAGE -o cyclonedx-json | astinus enrich --image $IMAGE -o enriched.cdx.json
```
 
Corporate registry (Artifactory) with auto-detected base image:
 
```bash
astinus enrich \
  --sbom syft.cdx.json \
  --image artifactory.corp.com/team/myapp:v1.2.3 \
  --base auto \
  --output enriched.cdx.json
```
 
Air-gapped environment with offline lookups:
 
```bash
astinus enrich \
  --sbom syft.cdx.json \
  --image-archive ./myapp.tar \
  --no-network \
  --offline-db /opt/astinus/db \
  --output enriched.cdx.json
```
 
## How It Works
 
```
┌──────────────┐     ┌──────────────┐     ┌──────────────────────┐
│  Your SBOM   │     │  Your Image  │     │  Optional Base Image │
│  (CDX/SPDX)  │     │  (any source)│     │  (auto or explicit)  │
└──────┬───────┘     └──────┬───────┘     └──────────┬───────────┘
       │                    │                        │
       └────────────────────┼────────────────────────┘
                            ▼
              ┌──────────────────────────┐
              │   Canonical SBOM Model   │
              └────────────┬─────────────┘
                           ▼
        ┌──────────────────────────────────────┐
        │       Enrichment Pipeline            │
        │  ┌────────────────────────────────┐  │
        │  │ Layer Attribution              │  │
        │  │ Base Image Diff                │  │
        │  │ Untracked Detection            │  │
        │  │ CPE Enrichment                 │  │
        │  │ <your custom enricher>         │  │
        │  └────────────────────────────────┘  │
        └──────────────────┬───────────────────┘
                           ▼
              ┌──────────────────────────┐
              │  Enriched SBOM           │
              │  (CDX, SPDX, SARIF,      │
              │   or summary report)     │
              └──────────────────────────┘
```
 
The pipeline is built around small, composable enrichers. Each enricher reads from and writes to a canonical internal SBOM model — this means new enrichers (e.g., compliance validators for region-specific regulations) can be added without touching the core.
 
## Built for CI/CD
 
Astinus is designed first and foremost as a command-line tool that fits into existing pipelines:
 
- **Single static binary** (`CGO_ENABLED=0`), no runtime dependencies
- **Stdin / stdout pipe-friendly** for streamed pipelines
- **Semantic exit codes** for granular CI failure handling
- **Structured JSON logs** auto-detected in CI environments
- **Stable, deterministic output** for diffing across runs
- **First-class corporate registry support** — JFrog Artifactory, Harbor, Nexus, ECR, GCR, ACR, GHCR
- **mTLS, custom CA bundles, and HTTP proxy** support out of the box
- **Air-gapped mode** with bundled offline databases
Reproducible builds, SLSA Level 3 provenance, and Cosign-signed releases are part of the v1.0 plan.
 
## Comparison
 
| | Syft alone | Syft + Astinus |
|---|:---:|:---:|
| Package-managed components (apt, apk, npm, …) | ✅ | ✅ |
| Vendored binaries (Go, Rust, static libs) | partial | ✅ |
| Embedded archives (JARs in WARs, etc.) | partial | ✅ |
| Layer attribution per component | ❌ | ✅ |
| Base image / application split | ❌ | ✅ |
| Auto base-image detection from labels | ❌ | ✅ |
| Reliable CPE for NVD matching | partial | ✅ |
| Provenance per component (which `RUN`/`COPY`) | ❌ | ✅ |
 
## Roadmap
 
The project is broken into 16 implementation stages. Current state:
 
- ✅ Specification finalized
- 🚧 **Stage 0**: Project bootstrap *(in progress)*
- ⬜ Stage 1: Canonical SBOM model + CycloneDX I/O
- ⬜ Stage 2: Image source foundation (registry + archive)
- ⬜ Stage 3: Pipeline + Layer Attribution enricher
- ⬜ Stage 4: Untracked components detection
- ⬜ Stage 5: Base image diff
- ⬜ Stage 6: CPE enrichment
- ⬜ Stage 7: SPDX support
- ⬜ Stages 8–15: Advanced auth, output formats, air-gapped mode, fingerprint matchers, policy framework, production polish
See the [full specification](docs/SPEC.md) for stage details and acceptance criteria.
 
## Extensibility
 
Astinus is designed to be extended without forking. The following extension points are first-class:
 
| Type | Interface | Use case |
|---|---|---|
| **Enricher** | `enrich.Enricher` | New sources of SBOM enrichment (e.g., internal license database) |
| **Validator** | `policy.Validator` | Compliance checks (EU CRA, FedRAMP, internal policies) |
| **Image Source** | `image.source.ImageSource` | Custom image storage backends |
| **Auth Provider** | `image.auth.CredentialProvider` | Corporate authentication systems |
| **Output Renderer** | `output.Renderer` | Internal report formats |
| **Fingerprint Matcher** | `fingerprint.matcher.Matcher` | Internal binary catalogs |
 
Custom builds are assembled by importing additional packages — no plugin system, no runtime overhead, no ABI compatibility headaches.
 
## Documentation
 
- [Full Specification](docs/SPEC.md) — detailed technical spec, architecture, and acceptance criteria
- [Architecture Overview](docs/architecture.md) *(coming with Stage 1)*
- [CI/CD Integration Guide](docs/ci-cd-integration.md) *(coming with Stage 11)*
- [Corporate Setup](docs/corporate-setup.md) — Artifactory, Harbor, mTLS, proxy, air-gapped *(coming with Stage 10)*
- [Extending Astinus](docs/extending.md) — writing custom enrichers and validators *(coming with Stage 14)*
## The Name
 
In the [Dragonlance](https://dragonlance.fandom.com/wiki/Astinus_of_Palanthas) setting, **Astinus of Palanthas** is the immortal Master Historian of Krynn. From the Great Library of Palanthas, he and his Order of Aesthetics continuously record every event in the world — meticulously, completely, without interpretation. The Chronicles of Krynn are never finished; they are always being added to.
 
The metaphor is direct. Your SBOM is a chronicle of what's inside your container. Existing tools draft it; Astinus continuously fills in what was missed.
 
## Contributing
 
The project is in early development. The most useful contributions right now are:
 
- **Issues**: Edge cases you'd want covered, gaps in the spec, ideas for enrichers
- **Real-world SBOMs and images** that demonstrate the gaps Astinus should close
- **Naming things**: if you spot a clearer term in the spec, suggest it
A formal contribution guide will land with v0.1.
 
## License
 
Astinus is released under the [Apache License 2.0](LICENSE).
 
## Acknowledgements
 
Astinus stands on the shoulders of the open-source SBOM community:
 
- [Anchore Syft](https://github.com/anchore/syft) — the SBOM generator Astinus is designed to enrich
- [CycloneDX](https://cyclonedx.org/) and [SPDX](https://spdx.dev/) — the standards we read and write
- [google/go-containerregistry](https://github.com/google/go-containerregistry) — the image abstraction we build on
- [ClearlyDefined](https://clearlydefined.io/) and [Software Heritage](https://www.softwareheritage.org/) — the catalogs we look up against