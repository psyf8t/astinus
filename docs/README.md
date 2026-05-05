# Astinus documentation

Start here:

- **[quickstart.md](quickstart.md)** — install, first enrich command, CI snippets. Five minutes.

Reference:

- **[configuration.md](configuration.md)** — every flag, every YAML key, exit codes.

Task-flavoured walkthroughs:

- **[corporate.md](corporate.md)** — Artifactory / Harbor / Nexus mirrors, mTLS, proxies, per-host auth.
- **[air-gapped.md](air-gapped.md)** — running with `--no-network`. Catalogue layout, refresh cadence.
- **[signing.md](signing.md)** — cosign sign + verify, key-based and keyless, in-toto attestations.
- **[compliance.md](compliance.md)** — `--fail-on`, the bundled NTIA / EU CRA validators, severity overrides.

Operations:

- **[releasing.md](releasing.md)** — release process, tagging, verifying release artifacts.

Architecture decisions live under [adr/](adr/) — one file per
material decision, dated, with the alternatives that were
considered.
