// Package config loads the per-run YAML configuration that ties
// per-registry auth + TLS settings together.
//
// Stage 10 only carries the registry-config subset because that's
// what mTLS / per-registry-config needs. Later stages can extend
// the top-level Config with logging / network / output / policies
// blocks (see spec section 7).
//
// Hierarchy (per ADR-0012):
//
//	CLI flags > per-registry config > global config > defaults
//
// Env vars are resolved as a separate axis at field load time —
// auth.token-env names a variable to read, not a literal secret.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level YAML schema. Stage 10 only populates
// Registries; later stages add Logging / Network / Output / Policies.
type Config struct {
	Version    int              `yaml:"version,omitempty"`
	Registries []RegistryConfig `yaml:"registries,omitempty"`
}

// RegistryConfig is one entry under registries:.
type RegistryConfig struct {
	// Host is the registry hostname (without scheme), e.g.
	// "artifactory.corp.com" or "harbor.corp.com:443".
	Host string `yaml:"host"`

	// Auth selects how credentials for this host are obtained.
	Auth *AuthConfig `yaml:"auth,omitempty"`

	// TLS holds custom CA / client certificate paths.
	TLS *TLSConfig `yaml:"tls,omitempty"`

	// Insecure permits HTTP connections (no TLS) to this host.
	Insecure bool `yaml:"insecure,omitempty"`

	// Proxy overrides the global proxy for this host. Empty value
	// means "use the env-driven default (HTTP_PROXY / NO_PROXY)".
	// "direct" or "none" means "skip proxy for this host".
	Proxy string `yaml:"proxy,omitempty"`
}

// AuthConfig is the per-host auth descriptor. Type names mirror
// spec section 9.4 (artifactory-token, artifactory-api-key,
// artifactory-oidc, basic, docker-config, ecr, gcr, acr).
type AuthConfig struct {
	// Type is the auth flavour.
	Type string `yaml:"type"`

	// Env-var names for the secrets. The provider reads these env
	// vars at runtime; the YAML never contains a secret.
	TokenEnv     string `yaml:"token-env,omitempty"`
	APIKeyEnv    string `yaml:"api-key-env,omitempty"`
	UsernameEnv  string `yaml:"username-env,omitempty"`
	PasswordEnv  string `yaml:"password-env,omitempty"`
	OIDCTokenEnv string `yaml:"oidc-token-env,omitempty"`

	// Audience is the OIDC audience claim used when the auth flow
	// performs a token exchange against the registry's endpoint.
	// Stage 10 stores it; Stage 9 follow-up wires the exchange.
	Audience string `yaml:"audience,omitempty"`
}

// TLSConfig holds per-host TLS material.
type TLSConfig struct {
	// CACert is the path to a PEM bundle merged into the system
	// CA pool for THIS registry only.
	CACert string `yaml:"ca-cert,omitempty"`

	// ClientCert + ClientKey form a PEM-encoded mTLS client
	// certificate pair.
	ClientCert string `yaml:"client-cert,omitempty"`
	ClientKey  string `yaml:"client-key,omitempty"`

	// SkipVerify disables TLS verification for this host.
	// Documented as "не рекомендуется" in spec section 6.2.
	SkipVerify bool `yaml:"skip-verify,omitempty"`
}

// Load reads path and parses it as YAML into Config.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("config: empty path")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	return Parse(body)
}

// Parse parses raw YAML bytes into Config. Useful for tests that
// don't want to touch disk.
func Parse(body []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate sanity-checks the loaded Config.
//
// Errors are explicit so the operator gets a clear message at CLI
// startup rather than a confusing failure during pull.
func (c *Config) Validate() error {
	for i, r := range c.Registries {
		if r.Host == "" {
			return fmt.Errorf("config: registries[%d]: host is required", i)
		}
		if r.TLS != nil {
			if (r.TLS.ClientCert == "") != (r.TLS.ClientKey == "") {
				return fmt.Errorf("config: registries[%d] (%s): client-cert and client-key must both be set or both empty",
					i, r.Host)
			}
		}
	}
	return nil
}

// HasPerRegistryTLS reports whether any registry entry carries TLS,
// proxy, or insecure overrides — i.e. whether per-host transport
// dispatch is needed at all.
func (c *Config) HasPerRegistryTLS() bool {
	if c == nil {
		return false
	}
	for _, r := range c.Registries {
		if r.TLS != nil || r.Insecure || r.Proxy != "" {
			return true
		}
	}
	return false
}

// FindRegistry returns the registry config that matches host (case-
// insensitive) or nil if none does.
func (c *Config) FindRegistry(host string) *RegistryConfig {
	if c == nil {
		return nil
	}
	for i := range c.Registries {
		if equalHost(c.Registries[i].Host, host) {
			return &c.Registries[i]
		}
	}
	return nil
}

// equalHost compares two host strings case-insensitively, treating
// "host:port" and "host" as different (matches Docker and OCI
// distribution behaviour).
func equalHost(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
