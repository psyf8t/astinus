//go:build acceptance

package helpers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// MirrorYAMLOpts is the small struct for templating a one-mirror
// MirrorsConfig YAML to disk. Sprint 3 acceptance tests only ever
// configure one or two mirrors; rather than wiring the full
// internal/config types in (build-tag boundary), we render the YAML
// directly.
type MirrorYAMLOpts struct {
	Ecosystem string // npm, pypi, maven, …
	URL       string
	Mode      string // replace | fallback (defaults to "replace")

	// Auth — exactly one of these blocks may be non-zero.
	BearerTokenEnv string
	BasicUser      string
	BasicPassEnv   string
	HeaderName     string
	HeaderValueEnv string

	// TLS material — paths to PEM files.
	CACert     string
	ClientCert string
	ClientKey  string
}

// WriteMirrorsConfig renders one or more MirrorYAMLOpts entries as a
// MirrorsConfig YAML file under dir (or tb.TempDir if empty), and
// returns the path. Caller passes that path to `--mirrors-config`.
//
// Cognitive complexity is dominated by the auth / TLS field
// rendering — kept as a flat if-tree rather than a registry of
// per-block formatters because each block prints exactly once and
// the indirection wouldn't help the reader.
//
//nolint:gocognit,gocyclo // see comment above
func WriteMirrorsConfig(tb testing.TB, dir string, mirrors ...MirrorYAMLOpts) string {
	tb.Helper()
	if dir == "" {
		dir = tb.TempDir()
	}
	var b strings.Builder
	b.WriteString("version: 1\nmirrors:\n")
	for _, m := range mirrors {
		mode := m.Mode
		if mode == "" {
			mode = "replace"
		}
		fmt.Fprintf(&b, "  - ecosystem: %s\n", m.Ecosystem)
		fmt.Fprintf(&b, "    url: %s\n", m.URL)
		fmt.Fprintf(&b, "    mode: %s\n", mode)
		switch {
		case m.BearerTokenEnv != "":
			fmt.Fprintf(&b, "    auth:\n      type: bearer\n      token_env: %s\n", m.BearerTokenEnv)
		case m.BasicUser != "" || m.BasicPassEnv != "":
			b.WriteString("    auth:\n      type: basic\n")
			if m.BasicUser != "" {
				fmt.Fprintf(&b, "      username: %s\n", m.BasicUser)
			}
			if m.BasicPassEnv != "" {
				fmt.Fprintf(&b, "      password_env: %s\n", m.BasicPassEnv)
			}
		case m.HeaderName != "" && m.HeaderValueEnv != "":
			fmt.Fprintf(&b, "    auth:\n      type: header\n      header_name: %s\n      header_value_env: %s\n",
				m.HeaderName, m.HeaderValueEnv)
		}
		if m.CACert != "" || m.ClientCert != "" || m.ClientKey != "" {
			b.WriteString("    tls:\n")
			if m.CACert != "" {
				fmt.Fprintf(&b, "      ca_cert: %s\n", m.CACert)
			}
			if m.ClientCert != "" {
				fmt.Fprintf(&b, "      client_cert: %s\n", m.ClientCert)
			}
			if m.ClientKey != "" {
				fmt.Fprintf(&b, "      client_key: %s\n", m.ClientKey)
			}
		}
	}
	path := filepath.Join(dir, "mirrors.yaml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		tb.Fatalf("write mirrors config: %v", err)
	}
	return path
}
