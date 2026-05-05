# Compliance findings and the `--fail-on` gate

Astinus runs a small set of compliance validators against the
enriched SBOM and surfaces the results in two ways: as
`astinus:compliance:*` properties on the SBOM root, and (when
asked) as a non-zero exit that breaks the build.

## What's checked

Two validator families ship out of the box:

**NTIA Minimum Elements** ([source](https://www.ntia.gov/page/software-bill-materials)).
The seven baseline fields the US government considers minimal for
a usable SBOM:

- supplier name
- component name
- component version
- unique identifier (PURL or CPE)
- dependency relationship (dependencies graph)
- author of the SBOM data
- timestamp

Per-component findings: `NTIA-MISSING-SUPPLIER`,
`NTIA-MISSING-LICENSE`, `NTIA-MISSING-VERSION`, etc.

**EU Cyber Resilience Act, Article 13** — manufacturer
obligations for software products. Notably:

- Each component must have a way to track vulnerabilities (CPE or
  similar identifier).
- License declarations must be present.
- The SBOM must be signed (covered by the signing workflow, not
  the validator).

Findings: `EU-CRA-ART13-VULN-HANDLING`, `EU-CRA-ART13-LICENSE`.

## Severity model

Each finding lands at one of five severities:

```
critical > high > medium > low > info > (ignored)
```

A blanket "everything is medium" approach generates thousands of
findings on real images — most of them noise (e.g. npm packages
that legitimately don't declare a supplier). Astinus ships with a
per-ecosystem severity policy:

| Rule | npm / pypi / deb / apk | maven / cargo / gem | golang | application binaries |
|---|---|---|---|---|
| NTIA-MISSING-SUPPLIER | info | low | medium | high |
| NTIA-MISSING-LICENSE | info | low | medium | high |
| NTIA-MISSING-VERSION | medium | medium | medium | high |
| EU-CRA-ART13-VULN-HANDLING | medium | medium | medium | high |
| EU-CRA-ART13-LICENSE | low | low | medium | high |

(Abbreviated — the full policy lives in
`internal/policy/builtin/compliance/severity_policy.go`.)

The reasoning: an npm package with no `author` field is normal;
an application binary with no supplier is a supply-chain risk.

## How findings surface

After an enrich run, the SBOM root carries:

```json
{
  "metadata": {
    "properties": [
      {"name": "astinus:compliance:findings-count", "value": "412"},
      {"name": "astinus:compliance:critical-count", "value": "0"},
      {"name": "astinus:compliance:high-count", "value": "3"},
      {"name": "astinus:compliance:medium-count", "value": "27"},
      {"name": "astinus:compliance:low-count", "value": "94"},
      {"name": "astinus:compliance:info-count", "value": "288"},
      {"name": "astinus:compliance:actionable-findings-count", "value": "30"}
    ]
  }
}
```

`actionable-findings-count` = `critical + high + medium`. It's
the number worth a human's attention after policy filtering.

For the per-finding details, write the SBOM as SARIF
(`--output-format sarif`) — each finding becomes a SARIF result
with rule id, severity, and the affected component as a logical
location. Drop into GitHub Code Scanning, GitLab CI, or any other
SARIF consumer.

## The `--fail-on` gate

```bash
astinus enrich --fail-on high ...
```

Exit code 40 if any finding (after policy filtering) is at or
above the chosen severity. Otherwise the run succeeds normally
and the SBOM is still written.

A typical CI usage:

```yaml
# .github/workflows/sbom.yml
- name: Enrich + gate
  run: |
    syft "$IMAGE" -o cyclonedx-json | astinus enrich \
      --sbom    - \
      --image   "$IMAGE" \
      --fail-on high \
      --output  enriched.cdx.json
```

If the build owns components with `high` findings, the step
fails. The `enriched.cdx.json` is still uploaded as an artefact
so a reviewer can see what tripped the gate.

The gate runs after signing — the SBOM is fully written and
signed even when the gate trips. That gives operators a usable
artefact to diagnose against.

## Severity overrides

When the bundled policy doesn't match your team's risk tolerance,
write a YAML override:

```yaml
# compliance.yaml
overrides:
  # Treat missing licenses as high for everything, not just for
  # application binaries.
  - rule: NTIA-MISSING-LICENSE
    severity: high

  # Demote a noisy rule to info.
  - rule: EU-CRA-ART13-LICENSE
    when:
      ecosystem: deb
    severity: info

  # Silence a rule entirely.
  - rule: NTIA-MISSING-SUPPLIER
    when:
      ecosystem: apk
    severity: ignored
```

Then point Astinus at it:

```bash
astinus enrich --compliance-config compliance.yaml ...
```

`severity: ignored` removes the finding before the gate sees it
— useful when a rule is genuinely non-actionable in your
environment (e.g. internal-only packages with no upstream
supplier concept).

## Picking the right `--fail-on` level

Loose recommendation, not gospel:

| Level | Use when |
|---|---|
| (unset) | You're producing SBOMs to ship downstream and a separate process owns vulnerability triage. |
| `high` | Production builds in a regulated environment. Catches application-binary licensing gaps + missing CPEs that would block vulnerability matching. |
| `medium` | Stricter — catches misconfigured Go modules and similar mid-tier issues. Expect more failures during initial rollout. |
| `low` / `info` | Investigation runs only — nearly every real image will trip these. |
| `critical` | The bundled rules don't currently emit `critical` — reserved for severe rules like "SBOM signed by a revoked key" once those validators ship. |

Roll out by starting with `--fail-on critical` (effectively a
no-op gate) so the SBOM job runs in CI without blocking, then
walk down the severities as you fix what's reported.

## What's NOT covered

- **Vulnerability findings** (CVE matches against the components).
  That's a vulnerability scanner's job — pair Astinus with Grype
  / OSV-Scanner / Trivy. Astinus's job is to make sure those
  tools have the CPEs / PURLs they need to do the matching.
- **License compatibility checks** (GPL contamination, dual-license
  conflicts, …). Another tool's job — feed enriched SBOMs to
  ScanCode, FOSSology, or your existing license workflow.
- **Per-rule SLA enforcement** (e.g. "fix high-severity findings
  within 7 days"). That's a tracking-system concern; Astinus
  emits the findings, your issue tracker / SLA platform owns the
  clock.

## Reading the SARIF output

```bash
astinus enrich --output-format sarif --output findings.sarif ...
```

```jsonc
{
  "runs": [{
    "tool": {"driver": {"name": "astinus", "rules": [...]}},
    "results": [
      {
        "ruleId": "NTIA-MISSING-LICENSE",
        "level": "warning",
        "message": {"text": "component lodash@4.17.20 has no license declaration"},
        "locations": [{
          "logicalLocations": [{"name": "pkg:npm/lodash@4.17.20"}]
        }]
      }
    ]
  }]
}
```

`level` reflects the post-policy severity (`error` → critical /
high, `warning` → medium / low, `note` → info). `ruleId` is
stable across versions — safe to filter on in downstream tooling.
