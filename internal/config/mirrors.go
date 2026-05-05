package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// MirrorsConfig is the on-disk schema for `--mirrors-config`. It
// configures package-registry mirrors (npm / PyPI / Maven / etc.)
// — separate concern from `Config.Registries` which targets image-pull
// registries (Stage 10).
//
// Naming: the YAML key is `mirrors:` rather than `registries:` to
// avoid confusion with `Config.Registries`. Each entry can be either
// a true mirror (Mode=replace forces the upstream offline) or an
// add-on (Mode=fallback tries the mirror first, then upstream).
//
// Sprint 3 Task 4 / ADR-0034.
type MirrorsConfig struct {
	Version int           `yaml:"version,omitempty"`
	Mirrors []MirrorEntry `yaml:"mirrors,omitempty"`
}

// MirrorEntry is one package-registry mirror. Multiple entries may
// target the same Ecosystem (e.g. internal Artifactory + public
// fallback) — the resolver tries them in declaration order, with
// replace-mode entries always tried before fallback-mode entries.
type MirrorEntry struct {
	// Ecosystem matches a PURL type ("npm", "pypi", "maven",
	// "cargo", "gem", "nuget", "golang", "deb", "apk",
	// "repology", "ecosyste-ms"). Lowercased on load.
	Ecosystem string `yaml:"ecosystem"`

	// URL is the mirror base URL (no trailing slash). The source
	// implementations append the path-suffix per ecosystem.
	URL string `yaml:"url"`

	// Mode controls fallback to the upstream public registry:
	//   - "replace" (default): use ONLY this mirror; never call
	//     upstream. The security default for air-gapped environments.
	//   - "fallback": try this mirror first; fall back to upstream
	//     on 404 or transient failure. Performance optimization for
	//     networked environments.
	Mode MirrorMode `yaml:"mode,omitempty"`

	// Auth selects how Astinus authenticates to this mirror.
	// Optional — public mirrors and unauthenticated reads work
	// without it.
	Auth *MirrorAuthConfig `yaml:"auth,omitempty"`

	// TLS holds per-mirror TLS material (custom CA bundle, mTLS
	// client cert / key). Optional.
	TLS *MirrorTLSConfig `yaml:"tls,omitempty"`

	// Headers is the bag of arbitrary headers to add to every
	// request — used for custom-auth schemes the AuthConfig types
	// don't model (e.g. JFrog's `X-JFrog-Art-Api`). Values may
	// reference env vars via `${VAR}` expansion at apply time.
	Headers map[string]string `yaml:"headers,omitempty"`

	// RateLimit applies a token-bucket rate limit to outbound
	// requests for this mirror. Optional — most mirrors don't need
	// it; some public APIs (e.g. Repology) require it.
	RateLimit *MirrorRateLimitConfig `yaml:"rate_limit,omitempty"`
}

// MirrorMode is the per-mirror upstream-fallback policy.
type MirrorMode string

const (
	// MirrorModeReplace makes the mirror the sole source — no
	// upstream fallback. Default when Mode is unset, because the
	// safer default for an air-gapped environment is "use only
	// what the operator approved".
	MirrorModeReplace MirrorMode = "replace"

	// MirrorModeFallback tries the mirror first and falls through
	// to the upstream public registry when the mirror returns 404
	// or a transient failure.
	MirrorModeFallback MirrorMode = "fallback"
)

// IsKnown reports whether m is a recognised mode.
func (m MirrorMode) IsKnown() bool {
	switch m {
	case MirrorModeReplace, MirrorModeFallback, "":
		return true
	default:
		return false
	}
}

// EffectiveMode normalises an empty/zero Mode to MirrorModeReplace
// (the security default).
func (m MirrorMode) EffectiveMode() MirrorMode {
	if m == "" {
		return MirrorModeReplace
	}
	return m
}

// MirrorAuthConfig is the per-mirror authentication descriptor.
// Three flavours: bearer / basic / header. Credentials never live
// in the YAML — they're read from env at apply time via the
// *Env fields.
type MirrorAuthConfig struct {
	// Type selects the auth flavour: "bearer" | "basic" | "header".
	Type string `yaml:"type"`

	// Bearer fields. Token is the literal value (DISCOURAGED — use
	// TokenEnv); TokenEnv names the env var that holds the token.
	Token    string `yaml:"token,omitempty"`
	TokenEnv string `yaml:"token_env,omitempty"`

	// Basic auth. Username may be in YAML; Password / PasswordEnv
	// hold the secret (PasswordEnv preferred).
	Username    string `yaml:"username,omitempty"`
	Password    string `yaml:"password,omitempty"`
	PasswordEnv string `yaml:"password_env,omitempty"`

	// Header auth — set HeaderName to a custom header name (e.g.
	// "X-JFrog-Art-Api") and HeaderValue/HeaderValueEnv to its
	// value.
	HeaderName     string `yaml:"header_name,omitempty"`
	HeaderValue    string `yaml:"header_value,omitempty"`
	HeaderValueEnv string `yaml:"header_value_env,omitempty"`
}

// MirrorTLSConfig holds per-mirror TLS material. Identical in
// purpose to TLSConfig (image-pull) but kept separate so each
// concern's schema can evolve independently.
type MirrorTLSConfig struct {
	// CACert is a PEM bundle path. Certificates are added to the
	// system pool, not replacing it.
	CACert string `yaml:"ca_cert,omitempty"`

	// ClientCert / ClientKey form a PEM-encoded mTLS client
	// certificate pair. Both must be set or both empty.
	ClientCert string `yaml:"client_cert,omitempty"`
	ClientKey  string `yaml:"client_key,omitempty"`

	// SkipVerify disables certificate validation. Off by default;
	// surfaced for dev environments only.
	SkipVerify bool `yaml:"insecure,omitempty"`
}

// MirrorRateLimitConfig caps outbound throughput to one mirror.
// Optional. RPS=0 means "no limit"; Burst defaults to 1.
type MirrorRateLimitConfig struct {
	RequestsPerSecond float64 `yaml:"rps"`
	Burst             int     `yaml:"burst"`
}

// LoadMirrorsConfig reads and parses a YAML file. Empty path
// returns an empty config (no mirrors). The caller passes the
// returned config to the registry resolver.
func LoadMirrorsConfig(path string) (*MirrorsConfig, error) {
	if path == "" {
		return &MirrorsConfig{}, nil
	}
	body, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("mirrors-config %q: %w", path, err)
	}
	return ParseMirrorsConfig(body)
}

// ParseMirrorsConfig parses YAML body into a MirrorsConfig and
// validates each entry. Used by tests + the file loader.
func ParseMirrorsConfig(body []byte) (*MirrorsConfig, error) {
	var cfg MirrorsConfig
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("mirrors-config: parse YAML: %w", err)
	}
	for i := range cfg.Mirrors {
		if err := validateMirror(&cfg.Mirrors[i]); err != nil {
			return nil, fmt.Errorf("mirrors-config: mirrors[%d]: %w", i, err)
		}
	}
	return &cfg, nil
}

// validateMirror enforces the per-entry invariants the resolver
// relies on. Mutates m to canonicalise enum-ish fields (lowercase
// ecosystem, default mode).
func validateMirror(m *MirrorEntry) error {
	if m.Ecosystem == "" {
		return fmt.Errorf("ecosystem is required")
	}
	if m.URL == "" {
		return fmt.Errorf("url is required")
	}
	if !m.Mode.IsKnown() {
		return fmt.Errorf("mode %q is not one of replace|fallback", m.Mode)
	}
	if m.Auth != nil {
		if err := validateMirrorAuth(m.Auth); err != nil {
			return err
		}
	}
	return nil
}

func validateMirrorAuth(a *MirrorAuthConfig) error {
	switch a.Type {
	case "bearer":
		if a.Token == "" && a.TokenEnv == "" {
			return fmt.Errorf("bearer auth: token or token_env is required")
		}
	case "basic":
		if a.Username == "" {
			return fmt.Errorf("basic auth: username is required")
		}
		if a.Password == "" && a.PasswordEnv == "" {
			return fmt.Errorf("basic auth: password or password_env is required")
		}
	case "header":
		if a.HeaderName == "" {
			return fmt.Errorf("header auth: header_name is required")
		}
		if a.HeaderValue == "" && a.HeaderValueEnv == "" {
			return fmt.Errorf("header auth: header_value or header_value_env is required")
		}
	default:
		return fmt.Errorf("unknown auth type %q (want bearer|basic|header)", a.Type)
	}
	return nil
}
