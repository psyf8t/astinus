package sources

import (
	"context"
	"encoding/xml"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/psyf8t/astinus/internal/config"
	"github.com/psyf8t/astinus/internal/enrich/cpe"
	"github.com/psyf8t/astinus/internal/enrich/registry"
)

// mavenUpstream is Maven Central's repo base. Operators typically
// override with internal Artifactory / Nexus / GitHub Packages.
const mavenUpstream = "https://repo1.maven.org/maven2"

// Maven fetches per-artefact `pom.xml` from Maven Central or
// operator-supplied mirrors. Path pattern:
//
//	<base>/<groupId-with-slashes>/<artifactId>/<version>/<artifactId>-<version>.pom
//
// PURL: `pkg:maven/<groupId>/<artifactId>@<version>` — Namespace
// = groupId, Name = artifactId.
type Maven struct {
	mirrors  []config.MirrorEntry
	client   *http.Client
	logger   *slog.Logger
	upstream string
}

// NewMaven returns a Maven Source.
func NewMaven(mirrors []config.MirrorEntry, client *http.Client) *Maven {
	if client == nil {
		client = registry.DefaultClient()
	}
	return &Maven{
		mirrors:  mirrors,
		client:   client,
		logger:   slog.Default(),
		upstream: mavenUpstream,
	}
}

// WithUpstream overrides the Maven Central base URL. Test-only.
func (m *Maven) WithUpstream(u string) *Maven { m.upstream = u; return m }

// WithLogger overrides the slog destination.
func (m *Maven) WithLogger(l *slog.Logger) *Maven {
	if l != nil {
		m.logger = l
	}
	return m
}

// Name implements registry.Source.
func (*Maven) Name() string { return "maven" }

// Supports implements registry.Source.
func (*Maven) Supports(t string) bool { return strings.EqualFold(t, "maven") }

// RequiresNetwork implements registry.Source.
func (*Maven) RequiresNetwork() bool { return true }

// Fetch implements registry.Source.
func (m *Maven) Fetch(ctx context.Context, p cpe.PURL) (*registry.Metadata, error) {
	if p.Namespace == "" || p.Name == "" || p.Version == "" {
		return nil, registry.ErrUnsupported
	}
	chain := registry.MirrorChain{Mirrors: m.mirrors, Upstream: m.upstream}

	groupPath := strings.ReplaceAll(p.Namespace, ".", "/")
	pathSuffix := "/" + groupPath + "/" + p.Name + "/" + p.Version + "/" + p.Name + "-" + p.Version + ".pom"

	var pom mavenPOM
	parser := func(body io.Reader) error {
		return xml.NewDecoder(body).Decode(&pom)
	}
	if err := registry.FetchJSON(ctx, m.client, chain, pathSuffix, m.Name(), parser, m.logger); err != nil {
		return nil, err
	}
	meta := convertMavenMetadata(&pom, p)
	if meta.IsEmpty() {
		return nil, registry.ErrNotFound
	}
	return meta, nil
}

// mavenPOM is the subset of Maven POM XML we read. Inheritance via
// `parent` is not resolved — we surface what's in the artefact's
// own pom.xml plus a flag noting it inherits (for diagnostics).
type mavenPOM struct {
	XMLName     xml.Name `xml:"project"`
	GroupID     string   `xml:"groupId"`
	ArtifactID  string   `xml:"artifactId"`
	Version     string   `xml:"version"`
	Name        string   `xml:"name"`
	Description string   `xml:"description"`
	URL         string   `xml:"url"`

	Licenses struct {
		License []struct {
			Name string `xml:"name"`
			URL  string `xml:"url"`
		} `xml:"license"`
	} `xml:"licenses"`

	Organization struct {
		Name string `xml:"name"`
		URL  string `xml:"url"`
	} `xml:"organization"`

	Developers struct {
		Developer []struct {
			Name  string `xml:"name"`
			Email string `xml:"email"`
			URL   string `xml:"url"`
		} `xml:"developer"`
	} `xml:"developers"`

	SCM struct {
		URL        string `xml:"url"`
		Connection string `xml:"connection"`
	} `xml:"scm"`

	IssueManagement struct {
		System string `xml:"system"`
		URL    string `xml:"url"`
	} `xml:"issueManagement"`
}

// convertMavenMetadata projects a parsed POM onto registry.Metadata.
// Maven licenses are recorded as free-form names (not always SPDX);
// we map a few common cases via mavenLicenseToSPDX, fall back to
// the raw Name otherwise.
func convertMavenMetadata(p *mavenPOM, purl cpe.PURL) *registry.Metadata {
	out := &registry.Metadata{
		Name:        p.ArtifactID,
		Version:     p.Version,
		Description: strings.TrimSpace(p.Description),
	}
	if out.Name == "" {
		out.Name = purl.Name
	}
	if out.Version == "" {
		out.Version = purl.Version
	}
	for _, l := range p.Licenses.License {
		if l.Name == "" {
			continue
		}
		spdx := mavenLicenseToSPDX(l.Name)
		out.Licenses = append(out.Licenses, registry.License{
			SPDXID: spdx,
			Name:   l.Name,
			URL:    l.URL,
		})
	}
	if p.Organization.Name != "" {
		out.Supplier.Name = p.Organization.Name
		out.Supplier.URL = p.Organization.URL
	} else if len(p.Developers.Developer) > 0 {
		dev := p.Developers.Developer[0]
		out.Author = dev.Name
		out.Supplier.Name = dev.Name
		out.Supplier.Email = dev.Email
		out.Supplier.URL = dev.URL
	}
	if out.Supplier.Name == "" && purl.Namespace != "" {
		// Fallback: groupId is often the org reverse-DNS.
		out.Supplier.Name = purl.Namespace
	}
	out.Homepage = p.URL
	out.Repository = cleanVCSURL(p.SCM.URL)
	if out.Repository == "" {
		out.Repository = cleanVCSURL(p.SCM.Connection)
	}
	out.BugTracker = p.IssueManagement.URL
	return out
}

// mavenLicenseToSPDX maps a few common Maven license names to SPDX
// identifiers. Conservative — only the clear cases. Unmapped
// names pass through as Name only (no SPDXID).
func mavenLicenseToSPDX(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.Contains(lower, "apache license, version 2.0"),
		strings.Contains(lower, "apache 2"),
		strings.Contains(lower, "apache-2.0"):
		return "Apache-2.0"
	case strings.Contains(lower, "mit license"), lower == "mit":
		return "MIT"
	case strings.Contains(lower, "bsd 3-clause"),
		strings.Contains(lower, "bsd-3-clause"):
		return "BSD-3-Clause"
	case strings.Contains(lower, "bsd 2-clause"),
		strings.Contains(lower, "bsd-2-clause"):
		return "BSD-2-Clause"
	case strings.Contains(lower, "eclipse public license 2"):
		return "EPL-2.0"
	case strings.Contains(lower, "eclipse public license 1"):
		return "EPL-1.0"
	case strings.Contains(lower, "gnu lesser general public license, version 2.1"):
		return "LGPL-2.1-only"
	case strings.Contains(lower, "gnu lesser general public license, version 3"):
		return "LGPL-3.0-only"
	case strings.Contains(lower, "isc"):
		return "ISC"
	}
	return ""
}
