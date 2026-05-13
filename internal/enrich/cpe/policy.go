package cpe

import "strings"

// EcosystemPolicy decides, per ecosystem, what the enricher does with
// CPE candidates for a Component:
//
//   - whether the primary CPE field on the Component is populated at
//     all (operators may want the CPE *known* but never *matched* by a
//     vulnerability scanner that keys on CPE — e.g. Go modules);
//   - which "vendor:product" pairs to reject before classification
//     (module-path TLDs like `go.uber.org` that NVD never registers,
//     yielding nothing but noise downstream);
//   - how to normalise the CPE version slot for that ecosystem (Go
//     modules natively store `vX.Y.Z`; NVD's CPE dictionary stores
//     `X.Y.Z`).
//
// Defaults are applied via DefaultPolicies; operator overrides are
// out of scope for S4 Task 3 (the YAML / CLI flag is documented in
// ADR-0042 as a future surface).
type EcosystemPolicy struct {
	// Ecosystem is the PURL type ("golang", "npm", "pypi", …). The
	// empty string is the fallback policy applied to PURL types
	// without an explicit entry.
	Ecosystem string

	// EmitPrimary controls whether the chosen primary candidate is
	// written to Component.CPEs. When false, no row makes it to the
	// scanner-facing field; the CPE still surfaces under
	// `astinus:cpe:evidence` (see EvidenceOnly).
	EmitPrimary bool

	// EvidenceOnly mirrors EmitPrimary == false: write the chosen
	// candidate to `astinus:cpe:evidence` instead of
	// Component.CPEs[0], plus the rationale property so consumers
	// understand why this row was de-promoted. Today
	// EvidenceOnly == !EmitPrimary; the second field exists for the
	// future where the two diverge (e.g. emit primary but also stamp
	// evidence for audit).
	EvidenceOnly bool

	// NormalizeVersion rewrites the CPE 2.3 version slot. Identity
	// for ecosystems that already speak NVD's version shape;
	// `stripVPrefix` for Go modules.
	NormalizeVersion func(string) string

	// RejectVendors is a small list of vendor literals the policy
	// considers structurally invalid for this ecosystem. Any
	// Candidate whose CPE vendor matches one of these is dropped
	// before classification. The match is case-insensitive and
	// exact; substrings don't count.
	RejectVendors []string

	// Rationale is the operator-visible justification stamped on the
	// Component as `astinus:cpe:rationale` when the primary CPE is
	// suppressed. Stays empty when the policy doesn't change
	// Component.CPEs.
	Rationale string

	// KeepPrimaryPurls is a narrow allow-list of PURL patterns
	// within this ecosystem that override `EmitPrimary = false`
	// and keep their primary CPE alongside the rest of the
	// ecosystem's demotion. S5 Task 0 introduced the field after
	// the over-broad golang demotion in ADR-0042 swallowed Go
	// stdlib (`cpe:2.3:a:golang:go:*`), which NVD does register
	// (351 entries) — net effect on a Grafana benchmark was 22
	// lost Go-runtime CVE matches vs Syft baseline.
	//
	// Pattern format: glob over the canonical PURL minus the
	// version. Examples:
	//
	//	"pkg:golang/stdlib"   exact match against `purl[:idx('@')]`
	//	"pkg:golang/cmd/*"    prefix glob (suffix `*` only)
	//
	// Matching is case-sensitive (PURL spec mandates lowercase
	// type / namespace / name segments). The check fires after
	// `RejectVendors` so policy-rejected vendors stay rejected.
	KeepPrimaryPurls []string

	// KeepPrimaryRationale is stamped on the matched component as
	// `astinus:cpe:exception-rationale` so SBOM consumers can
	// distinguish "policy kept this primary" from "policy didn't
	// fire on this component". S5 Task 0.
	KeepPrimaryRationale string
}

// DefaultPolicies returns the per-ecosystem CPE policy table the
// enricher applies in production. The set is intentionally small;
// new ecosystems only need an entry when the default policy
// (`EmitPrimary = true`, no version normalisation, no rejected
// vendors) is wrong for them.
//
// S4 Task 3 added the `golang` entry after a real-image audit found
// 0/10 sampled Go-module CPEs matched NVD: the vendor (`go.uber.org`
// etc.) is a module-path TLD NVD does not register, and Syft emits
// `:vX.Y.Z:` in the CPE version slot where NVD stores `:X.Y.Z:`.
// The policy demotes Go-module CPEs to evidence-only so they survive
// in the SBOM for transparency but stop expanding the vulnerability
// scanner's match surface with rows that can never match.
func DefaultPolicies() map[string]*EcosystemPolicy {
	return map[string]*EcosystemPolicy{
		"golang": {
			Ecosystem:        "golang",
			EmitPrimary:      false,
			EvidenceOnly:     true,
			NormalizeVersion: stripVPrefix,
			RejectVendors: []string{
				"go.uber.org",
				"k8s.io",
				"kubernetes.io",
				"gopkg.in",
				"cel.dev",
				"modernc.org",
				"go.opentelemetry.io",
				"go.etcd.io",
				"sigs.k8s.io",
				"knative.dev",
				"src-d",
			},
			Rationale: "Go module paths are not registered as vendor:product pairs " +
				"in the NVD CPE dictionary. Emitting a CPE in the primary field " +
				"creates misleading match surface for vulnerability scanners that " +
				"key on CPE. The CPE is preserved under astinus:cpe:evidence for " +
				"audit purposes.",
			KeepPrimaryPurls: []string{
				// Go standard library — `vendor=golang, product=go` is
				// the NVD-registered identifier (351 entries as of
				// ADR-0047). The over-broad ADR-0042 demotion sent it
				// to evidence-only, costing 22 Grype matches on a real
				// Grafana benchmark; this exception restores it.
				"pkg:golang/stdlib",
			},
			KeepPrimaryRationale: "Go standard library is registered in the NVD CPE " +
				"dictionary as vendor=golang product=go. Primary CPE preserved for " +
				"vulnerability scanners to match Go runtime CVEs. ADR-0047.",
		},
		"npm":   {Ecosystem: "npm", EmitPrimary: true, NormalizeVersion: identityVersion},
		"pypi":  {Ecosystem: "pypi", EmitPrimary: true, NormalizeVersion: identityVersion},
		"maven": {Ecosystem: "maven", EmitPrimary: true, NormalizeVersion: identityVersion},
		"apk":   {Ecosystem: "apk", EmitPrimary: true, NormalizeVersion: identityVersion},
		"deb":   {Ecosystem: "deb", EmitPrimary: true, NormalizeVersion: identityVersion},
		"rpm":   {Ecosystem: "rpm", EmitPrimary: true, NormalizeVersion: identityVersion},
		// Fallback: any ecosystem we don't explicitly know about keeps the
		// pre-S4-Task-3 default.
		"": {Ecosystem: "default", EmitPrimary: true, NormalizeVersion: identityVersion},
	}
}

// policyForEcosystem returns the policy for the given ecosystem,
// falling back to the empty-string default. Always returns a
// non-nil pointer.
func policyForEcosystem(policies map[string]*EcosystemPolicy, ecosystem string) *EcosystemPolicy {
	if p, ok := policies[ecosystem]; ok && p != nil {
		return p
	}
	if p, ok := policies[""]; ok && p != nil {
		return p
	}
	return &EcosystemPolicy{Ecosystem: "default", EmitPrimary: true, NormalizeVersion: identityVersion}
}

// stripVPrefix removes the leading `v` from a Go-toolchain version.
// `v1.2.3` → `1.2.3`. Leaves already-stripped, empty, or
// `(devel)`-marker strings alone.
func stripVPrefix(v string) string {
	if v == "(devel)" || v == "" {
		return v
	}
	return strings.TrimPrefix(v, "v")
}

// identityVersion is the no-op normaliser used by ecosystems whose
// version shape already matches NVD's CPE dictionary.
func identityVersion(v string) string { return v }

// applyVersionNormalization rewrites the version slot of a CPE 2.3
// URI via fn. Returns the original string when the input doesn't
// look like a CPE 2.3 URI (so the helper is safe to call on
// arbitrary candidate CPEs without a pre-check).
//
// CPE 2.3 shape (13 colon-separated fields):
//
//	cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:
//	    <language>:<sw_edition>:<target_sw>:<target_hw>:<other>
func applyVersionNormalization(cpe string, fn func(string) string) string {
	if fn == nil {
		return cpe
	}
	parts := strings.SplitN(cpe, ":", 13)
	if len(parts) < 6 || parts[0] != "cpe" {
		return cpe
	}
	parts[5] = fn(parts[5])
	return strings.Join(parts, ":")
}

// cpeVendor returns the vendor segment (field index 3) of a CPE 2.3
// URI, lowercased. Returns "" when the input doesn't parse as CPE
// 2.3.
func cpeVendor(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 4 || parts[0] != "cpe" {
		return ""
	}
	return strings.ToLower(parts[3])
}

// matchesAnyVendor reports whether vendor equals (case-insensitive)
// any of the rejectList entries.
func matchesAnyVendor(vendor string, rejectList []string) bool {
	v := strings.ToLower(vendor)
	for _, r := range rejectList {
		if strings.ToLower(r) == v {
			return true
		}
	}
	return false
}

// matchesKeepPrimary reports whether the Component's PURL falls
// inside the ecosystem policy's KeepPrimary allow-list. The match
// strips the version (`pkg:golang/stdlib@1.25.9` → `pkg:golang/stdlib`)
// before comparing, since the same PURL coordinate carries every
// version of the library across catalogue refreshes. Supports
// exact match and a trailing `*` glob (no other wildcard syntax).
// S5 Task 0.
func matchesKeepPrimary(purl string, patterns []string) bool {
	if purl == "" || len(patterns) == 0 {
		return false
	}
	base := purl
	if i := strings.IndexByte(purl, '@'); i > 0 {
		base = purl[:i]
	}
	if j := strings.IndexByte(base, '?'); j > 0 {
		base = base[:j]
	}
	for _, pat := range patterns {
		if pat == "" {
			continue
		}
		if strings.HasSuffix(pat, "*") {
			prefix := strings.TrimSuffix(pat, "*")
			if strings.HasPrefix(base, prefix) {
				return true
			}
			continue
		}
		if pat == base {
			return true
		}
	}
	return false
}
