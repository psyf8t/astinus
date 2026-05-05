# Security policy

## Supported versions

Astinus is in pre-1.0 development. Only the latest tagged release is
supported with security fixes.

| Version | Supported |
|---|---|
| Latest tagged release (`v0.x.y`) | ✅ |
| Older tags | ❌ |
| `dev` branch | ⚠️ unstable |

Once Astinus reaches v1.0, the support window will be specified
explicitly here.

## Reporting a vulnerability

**Please do not file public GitHub issues for security
vulnerabilities.** Use:

**[GitHub Security Advisories — open a private advisory](https://github.com/psyf8t/astinus/security/advisories/new)**

This is the only supported channel. Public advisories are still
welcome once a fix is shipped.

Please include:

- Affected version (output of `astinus version`)
- Reproducer (smallest possible — a synthetic SBOM + image works
  better than a real one)
- Expected vs actual behaviour
- Whether you'd like credit in the advisory (we'll credit by default)

## Response targets

- **Acknowledgement:** within 3 working days
- **Triage:** within 7 working days
- **Fix or mitigation:** depends on severity, but a written timeline
  within 14 working days

## Scope

Things we treat as security issues:

- Code that runs as a result of processing a malicious SBOM input
- Privilege escalation through container image processing
- Sensitive data leakage in logs (auth headers, keys, …)
- Supply-chain integrity issues with our own release artifacts
  (sigstore mis-issuance, etc.)
- DoS through algorithmic complexity in the path classifier or
  CPE matcher

Things we do **not** treat as security issues:

- Reports of false-positive or false-negative SBOM entries — those
  are correctness issues; please file as regular issues
- "Astinus didn't catch this CVE in my container" — that's a
  vulnerability scanner's question, not Astinus's; pair with Grype,
  OSV-Scanner, or Trivy

## Hardening

For operators running Astinus in production:

- Use the distroless container image (`ghcr.io/psyf8t/astinus`)
- Pin the version (avoid `:latest` in CI)
- Verify release artifacts with cosign — the verification command is
  in each release's footer on the [Releases page](https://github.com/psyf8t/astinus/releases)
- Run with `--no-network` if your environment has no outbound
  internet access — see [docs/air-gapped.md](docs/air-gapped.md)
