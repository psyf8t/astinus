package sources

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/psyf8t/astinus/internal/config"
	"github.com/psyf8t/astinus/internal/enrich/cpe"
	"github.com/psyf8t/astinus/internal/enrich/registry"
)

// npmUpstream is the public npmjs.org base URL. Surfaced as a const
// so tests can swap with httptest.Server via WithUpstream.
const npmUpstream = "https://registry.npmjs.org"

// NPM fetches package metadata from npmjs.org or operator-supplied
// mirrors (Artifactory npm-virtual, Verdaccio, GitHub Packages npm).
//
// Endpoint pattern: `<base>/<scope%2Fname>/<version>` for scoped
// packages, `<base>/<name>/<version>` otherwise.
type NPM struct {
	mirrors  []config.MirrorEntry
	client   *http.Client
	logger   *slog.Logger
	upstream string
}

// NewNPM returns an NPM Source. Pass nil client to use
// `registry.DefaultClient` (env-proxy honoured).
func NewNPM(mirrors []config.MirrorEntry, client *http.Client) *NPM {
	if client == nil {
		client = registry.DefaultClient()
	}
	return &NPM{
		mirrors:  mirrors,
		client:   client,
		logger:   slog.Default(),
		upstream: npmUpstream,
	}
}

// WithUpstream overrides the npmjs.org base URL. Test-only.
func (n *NPM) WithUpstream(u string) *NPM {
	n.upstream = u
	return n
}

// WithLogger overrides the slog destination. Used by tests to
// silence per-request debug logs.
func (n *NPM) WithLogger(l *slog.Logger) *NPM {
	if l != nil {
		n.logger = l
	}
	return n
}

// Name implements registry.Source.
func (*NPM) Name() string { return "npm" }

// Supports implements registry.Source.
func (*NPM) Supports(t string) bool { return strings.EqualFold(t, "npm") }

// RequiresNetwork implements registry.Source.
func (*NPM) RequiresNetwork() bool { return true }

// Fetch implements registry.Source.
func (n *NPM) Fetch(ctx context.Context, p cpe.PURL) (*registry.Metadata, error) {
	if p.Name == "" || p.Version == "" {
		return nil, registry.ErrUnsupported
	}
	chain := registry.MirrorChain{
		Mirrors:  n.mirrors,
		Upstream: n.upstream,
	}

	var raw npmPackageVersion
	parser := func(body io.Reader) error {
		return json.NewDecoder(body).Decode(&raw)
	}
	if err := registry.FetchJSON(ctx, n.client, chain, npmPathFor(p), n.Name(), parser, n.logger); err != nil {
		return nil, err
	}
	meta := convertNPMMetadata(&raw)
	if meta.IsEmpty() {
		return nil, registry.ErrNotFound
	}
	return meta, nil
}

// npmPathFor returns the canonical lookup path for one PURL.
// Scoped packages (`@scope/name`) use the URL-encoded form
// `@scope%2Fname` per the npm registry spec.
func npmPathFor(p cpe.PURL) string {
	name := p.Name
	if p.Namespace != "" {
		// PURL namespace for npm is the scope (with leading @).
		name = url.PathEscape(p.Namespace + "/" + p.Name)
	}
	return "/" + name + "/" + url.PathEscape(p.Version)
}

// npmPackageVersion is the subset of the npm per-version response
// we read. Schema documented at https://docs.npmjs.com/cli/v9/configuring-npm/package-json
type npmPackageVersion struct {
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description"`
	License     json.RawMessage `json:"license"`
	Licenses    json.RawMessage `json:"licenses"`
	Author      json.RawMessage `json:"author"`
	Homepage    string          `json:"homepage"`
	Repository  json.RawMessage `json:"repository"`
	Bugs        json.RawMessage `json:"bugs"`
	Maintainers []npmAuthor     `json:"maintainers"`
	Dist        npmDist         `json:"dist"`
}

type npmAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	URL   string `json:"url"`
}

type npmDist struct {
	Shasum    string `json:"shasum"`
	Integrity string `json:"integrity"`
}

// convertNPMMetadata projects a parsed npm response onto the
// registry.Metadata shape. License normalisation per
// `licenseFromString` (handles SPDX expressions, the legacy
// `licenses[]` array, and `UNLICENSED` private-package marker).
func convertNPMMetadata(raw *npmPackageVersion) *registry.Metadata {
	out := &registry.Metadata{
		Name:        raw.Name,
		Version:     raw.Version,
		Description: raw.Description,
		Hashes:      map[string]string{},
	}
	if licenses := normalizeNPMLicense(raw.License); len(licenses) > 0 {
		out.Licenses = licenses
	} else if licenses := normalizeNPMLicenses(raw.Licenses); len(licenses) > 0 {
		out.Licenses = licenses
	}
	if author := decodeNPMAuthor(raw.Author); author.Name != "" {
		out.Author = author.Name
		out.Supplier.Name = author.Name
		out.Supplier.URL = author.URL
		out.Supplier.Email = author.Email
	}
	for _, m := range raw.Maintainers {
		out.Maintainers = append(out.Maintainers, registry.Maintainer{
			Name: m.Name, Email: m.Email, URL: m.URL,
		})
	}
	if out.Supplier.Name == "" && len(raw.Maintainers) > 0 {
		out.Supplier.Name = raw.Maintainers[0].Name
		out.Supplier.Email = raw.Maintainers[0].Email
	}
	out.Homepage = raw.Homepage
	out.Repository = decodeNPMRepository(raw.Repository)
	out.BugTracker = decodeNPMBugs(raw.Bugs)
	if raw.Dist.Shasum != "" {
		out.Hashes["sha1"] = raw.Dist.Shasum
	}
	if raw.Dist.Integrity != "" {
		alg, hex := parseSubresourceIntegrity(raw.Dist.Integrity)
		if alg != "" {
			out.Hashes[alg] = hex
		}
	}
	if len(out.Hashes) == 0 {
		out.Hashes = nil
	}
	return out
}

// normalizeNPMLicense handles npm's `license` field which can be:
//   - "MIT"
//   - { "type": "MIT", "url": "..." }
//   - "(MIT OR Apache-2.0)" (an SPDX expression)
//   - "UNLICENSED" (private package — not SPDX, drop)
//   - "SEE LICENSE IN LICENSE.txt" (free-form, retain as Name)
func normalizeNPMLicense(raw json.RawMessage) []registry.License {
	if len(raw) == 0 {
		return nil
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return licenseFromString(asString)
	}
	var asObject struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	if err := json.Unmarshal(raw, &asObject); err == nil && asObject.Type != "" {
		return licenseFromString(asObject.Type)
	}
	return nil
}

// normalizeNPMLicenses handles npm's deprecated `licenses` array
// (legacy package.json shape).
func normalizeNPMLicenses(raw json.RawMessage) []registry.License {
	if len(raw) == 0 {
		return nil
	}
	var asArray []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	if err := json.Unmarshal(raw, &asArray); err != nil {
		return nil
	}
	var out []registry.License
	for _, l := range asArray {
		if l.Type == "" {
			continue
		}
		out = append(out, licenseFromString(l.Type)...)
	}
	return out
}

// licenseFromString classifies a single license string as either
// SPDX expression / SPDX id / free-form name / drop. Handles the
// special case `UNLICENSED` which signals a private package, not
// a real license — we drop it.
func licenseFromString(s string) []registry.License {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "UNLICENSED") {
		return nil
	}
	// SPDX expressions are wrapped in parens or contain OR / AND.
	if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		expr := strings.TrimSpace(s[1 : len(s)-1])
		return []registry.License{{Name: expr}}
	}
	if strings.Contains(s, " OR ") || strings.Contains(s, " AND ") || strings.Contains(s, " WITH ") {
		return []registry.License{{Name: s}}
	}
	// "SEE LICENSE IN LICENSE.txt" / "Custom" — keep as Name.
	if strings.HasPrefix(strings.ToUpper(s), "SEE LICENSE") || strings.Contains(s, " ") {
		return []registry.License{{Name: s}}
	}
	return []registry.License{{SPDXID: s, Name: s}}
}

// decodeNPMAuthor handles npm's `author` field which can be:
//   - "Name <email> (url)"
//   - { "name": "...", "email": "...", "url": "..." }
func decodeNPMAuthor(raw json.RawMessage) npmAuthor {
	if len(raw) == 0 {
		return npmAuthor{}
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return parseNPMAuthorString(asString)
	}
	var asObject npmAuthor
	if err := json.Unmarshal(raw, &asObject); err == nil {
		return asObject
	}
	return npmAuthor{}
}

// parseNPMAuthorString decodes "Name <email> (url)" into the
// structured form. Tolerant of missing fields.
func parseNPMAuthorString(s string) npmAuthor {
	out := npmAuthor{}
	rest := strings.TrimSpace(s)
	if i := strings.Index(rest, "("); i >= 0 {
		if j := strings.Index(rest[i+1:], ")"); j >= 0 {
			out.URL = strings.TrimSpace(rest[i+1 : i+1+j])
			rest = strings.TrimSpace(rest[:i] + rest[i+1+j+1:])
		}
	}
	if i := strings.Index(rest, "<"); i >= 0 {
		if j := strings.Index(rest[i+1:], ">"); j >= 0 {
			out.Email = strings.TrimSpace(rest[i+1 : i+1+j])
			rest = strings.TrimSpace(rest[:i] + rest[i+1+j+1:])
		}
	}
	out.Name = strings.TrimSpace(rest)
	return out
}

// decodeNPMRepository extracts a usable VCS URL from npm's
// `repository` field which can be a string or an object with type
// + url. Strips the conventional `git+` prefix and `.git` suffix.
func decodeNPMRepository(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return cleanVCSURL(asString)
	}
	var asObject struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	if err := json.Unmarshal(raw, &asObject); err == nil {
		return cleanVCSURL(asObject.URL)
	}
	return ""
}

func decodeNPMBugs(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return asString
	}
	var asObject struct {
		URL   string `json:"url"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(raw, &asObject); err == nil {
		return asObject.URL
	}
	return ""
}

// cleanVCSURL strips the `git+` prefix and `.git` suffix npm
// commonly carries on repository URLs, leaving a browseable URL.
//
// The `.git` strip is conservative: it only fires when `.git` sits
// at the URL end without a query string. Apache Gitweb URLs like
// `https://gitbox.apache.org/repos/asf?p=commons-lang.git` carry
// `.git` as a query value and stripping it would corrupt them.
func cleanVCSURL(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimPrefix(u, "git+")
	if strings.ContainsAny(u, "?#") {
		return u
	}
	return strings.TrimSuffix(u, ".git")
}

// parseSubresourceIntegrity decodes a Subresource Integrity hash
// string (`sha512-<base64>`) into (algorithm, hex). Returns empty
// strings on parse failure.
func parseSubresourceIntegrity(integrity string) (string, string) {
	parts := strings.SplitN(integrity, "-", 2)
	if len(parts) != 2 {
		return "", ""
	}
	alg := strings.ToLower(strings.TrimSpace(parts[0]))
	switch alg {
	case "sha256", "sha384", "sha512":
		hex := decodeBase64ToHex(parts[1])
		if hex == "" {
			return "", ""
		}
		return alg, hex
	}
	return "", ""
}
