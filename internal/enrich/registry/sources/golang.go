package sources

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/psyf8t/astinus/internal/config"
	"github.com/psyf8t/astinus/internal/enrich/cpe"
	"github.com/psyf8t/astinus/internal/enrich/registry"
)

// golangUpstream is the public Go module proxy. Operators with
// `GOPROXY=https://goproxy.corp` set a mirror via the standard
// MirrorEntry config.
const golangUpstream = "https://proxy.golang.org"

// Golang fetches metadata from the Go module proxy protocol
// (https://go.dev/ref/mod#module-proxy):
//
//   - <base>/<module>/@v/<version>.info  → JSON {Version, Time}
//   - <base>/<module>/@v/<version>.mod   → go.mod text (we read
//     `module` line for completeness; the proxy doesn't carry
//     license / homepage / supplier metadata).
//
// Module path is case-encoded per the spec
// (https://go.dev/ref/mod#goproxy-protocol §3.1) — uppercase
// letters become `!a..!z`. Implemented in escapeModulePath.
//
// What we get from the proxy:
//
//   - .info gives Version + Time only (no homepage/license/etc.)
//   - .mod gives the module's own go.mod (transitive deps)
//
// Conclusion: the GOPROXY protocol carries less metadata than
// other ecosystems. We populate Version + a synthetic Repository
// derived from the module path (`github.com/x/y` → `https://...`)
// and a placeholder Description noting the limitation. License /
// Supplier require pkg.go.dev or VCS scraping — deferred.
type Golang struct {
	mirrors  []config.MirrorEntry
	client   *http.Client
	logger   *slog.Logger
	upstream string
}

// NewGolang returns a Golang Source.
func NewGolang(mirrors []config.MirrorEntry, client *http.Client) *Golang {
	if client == nil {
		client = registry.DefaultClient()
	}
	return &Golang{
		mirrors:  mirrors,
		client:   client,
		logger:   slog.Default(),
		upstream: golangUpstream,
	}
}

// WithUpstream overrides proxy.golang.org. Test-only.
func (g *Golang) WithUpstream(u string) *Golang { g.upstream = u; return g }

// WithLogger overrides the slog destination.
func (g *Golang) WithLogger(l *slog.Logger) *Golang {
	if l != nil {
		g.logger = l
	}
	return g
}

// Name implements registry.Source.
func (*Golang) Name() string { return "golang" }

// Supports implements registry.Source.
func (*Golang) Supports(t string) bool { return strings.EqualFold(t, "golang") }

// RequiresNetwork implements registry.Source.
func (*Golang) RequiresNetwork() bool { return true }

// Fetch implements registry.Source.
func (g *Golang) Fetch(ctx context.Context, p cpe.PURL) (*registry.Metadata, error) {
	if p.Name == "" || p.Version == "" {
		return nil, registry.ErrUnsupported
	}
	module := joinGolangModule(p)
	encoded := escapeModulePath(module)
	chain := registry.MirrorChain{Mirrors: g.mirrors, Upstream: g.upstream}

	// .info gives us a confirmed Version.
	infoSuffix := "/" + encoded + "/@v/" + p.Version + ".info"
	var info golangModuleInfo
	if err := registry.FetchJSON(ctx, g.client, chain, infoSuffix, g.Name(),
		func(body io.Reader) error { return json.NewDecoder(body).Decode(&info) },
		g.logger); err != nil {
		return nil, err
	}

	// .mod gives us the module's own go.mod for the module-path
	// header (which is what we already have, but confirms the
	// proxy's response).
	modSuffix := "/" + encoded + "/@v/" + p.Version + ".mod"
	_ = modSuffix // reserved for future deps extraction; skipped today

	meta := &registry.Metadata{
		Name:        module,
		Version:     info.Version,
		Description: "Go module — registry-proxy metadata only carries Version+Time; pkg.go.dev scraping deferred (see ADR-0033 §6 follow-ups).",
		Repository:  golangVCSGuess(module),
	}
	if meta.Version == "" {
		meta.Version = p.Version
	}
	return meta, nil
}

// golangModuleInfo is the proxy's `.info` response. Time is not
// projected today; reserved.
type golangModuleInfo struct {
	Version string `json:"Version"`
	Time    string `json:"Time"`
}

// joinGolangModule reconstructs the canonical Go module path from
// a parsed PURL. PURL: `pkg:golang/<host>/<user>/<name>@<v>`.
// Namespace = `<host>/<user>`; Name = `<name>`. The module path is
// `<host>/<user>/<name>`.
func joinGolangModule(p cpe.PURL) string {
	if p.Namespace == "" {
		return p.Name
	}
	return p.Namespace + "/" + p.Name
}

// escapeModulePath applies the GOPROXY case-encoding rule (spec
// §3.1): uppercase letters become `!<lowercase>` so case-insensitive
// filesystems disambiguate paths.
func escapeModulePath(module string) string {
	var b strings.Builder
	b.Grow(len(module) + 8)
	for _, r := range module {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// golangVCSGuess infers the VCS URL from a Go module path. Module
// paths starting with a known forge host are predictable: each
// host maps to a `https://<host>/<user>/<repo>` URL.
func golangVCSGuess(module string) string {
	for _, prefix := range []string{
		"github.com/", "gitlab.com/", "bitbucket.org/", "codeberg.org/",
		"sr.ht/~", "git.sr.ht/~",
	} {
		if strings.HasPrefix(module, prefix) {
			rest := module[len(prefix):]
			parts := strings.SplitN(rest, "/", 3)
			if len(parts) >= 2 {
				return "https://" + prefix + parts[0] + "/" + parts[1]
			}
		}
	}
	return ""
}

// readModFile reads the proxy's `.mod` response and extracts the
// `module` line. Reserved for a future iteration that also lifts
// transitive `require` entries into SubComponents the way the
// extractor enricher does for binaries.
func readModFile(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if rest, ok := strings.CutPrefix(line, "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	return ""
}
