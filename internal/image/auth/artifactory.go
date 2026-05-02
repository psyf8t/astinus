package auth

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// ArtifactoryMode selects how the provider obtains credentials.
type ArtifactoryMode int

const (
	// ArtifactoryToken is JFrog's recommended access-token flow:
	// `Authorization: Bearer <token>`. Token is read from
	// ArtifactoryConfig.TokenEnv.
	ArtifactoryToken ArtifactoryMode = iota
	// ArtifactoryAPIKey is the legacy basic-auth flow with
	// username + API key.
	ArtifactoryAPIKey
	// ArtifactoryOIDC reads a JWT from the CI environment (e.g.
	// GITHUB_TOKEN) and presents it as a bearer token. Real OIDC
	// exchange against Artifactory's token endpoint is a future
	// extension; for the common case the JWT itself is what
	// Artifactory accepts.
	ArtifactoryOIDC
)

// ArtifactoryConfig configures one Artifactory provider instance.
//
// Hosts narrows where the provider applies. When non-empty, only
// hosts that exactly match a Hosts entry (case-insensitive) get
// served. Empty Hosts means "every host that looks like Artifactory"
// — see hostLooksLikeArtifactory.
//
// Env-var fields hold the NAME of the env var the provider reads, not
// the secret itself. This keeps secrets out of the config file when
// the provider is constructed from YAML.
type ArtifactoryConfig struct {
	Mode         ArtifactoryMode
	Hosts        []string
	TokenEnv     string
	UserEnv      string
	APIKeyEnv    string
	OIDCTokenEnv string
}

// ArtifactoryProvider implements CredentialProvider for JFrog
// Artifactory and registries that imitate its auth shape (Harbor's
// robot accounts, Nexus's docker proxy, etc.).
type ArtifactoryProvider struct {
	cfg    ArtifactoryConfig
	getenv func(string) string
}

// NewArtifactoryProvider returns a provider with the supplied config.
func NewArtifactoryProvider(cfg ArtifactoryConfig) *ArtifactoryProvider {
	return &ArtifactoryProvider{cfg: cfg, getenv: os.Getenv}
}

// Name implements CredentialProvider.
func (p *ArtifactoryProvider) Name() string { return "artifactory" }

// Resolve implements CredentialProvider.
func (p *ArtifactoryProvider) Resolve(_ context.Context, host string) (Credentials, error) {
	if !p.appliesTo(host) {
		return Credentials{}, fmt.Errorf("artifactory: host %q out of scope: %w", host, ErrNoCredentials)
	}
	get := p.getenv
	if get == nil {
		get = os.Getenv
	}

	switch p.cfg.Mode {
	case ArtifactoryToken:
		token := readEnvFallback(get, p.cfg.TokenEnv, "ARTIFACTORY_TOKEN")
		if token == "" {
			return Credentials{}, fmt.Errorf("artifactory: token env empty for %q: %w", host, ErrNoCredentials)
		}
		return Credentials{Token: token}, nil

	case ArtifactoryAPIKey:
		user := readEnvFallback(get, p.cfg.UserEnv, "ARTIFACTORY_USER")
		key := readEnvFallback(get, p.cfg.APIKeyEnv, "ARTIFACTORY_API_KEY")
		if user == "" || key == "" {
			return Credentials{}, fmt.Errorf("artifactory: api-key env(s) empty for %q: %w", host, ErrNoCredentials)
		}
		return Credentials{Username: user, Password: key}, nil

	case ArtifactoryOIDC:
		token := readEnvFallback(get, p.cfg.OIDCTokenEnv, "GITHUB_TOKEN", "GITLAB_OIDC_TOKEN")
		if token == "" {
			return Credentials{}, fmt.Errorf("artifactory: OIDC token env empty for %q: %w", host, ErrNoCredentials)
		}
		return Credentials{Token: token}, nil
	}
	return Credentials{}, fmt.Errorf("artifactory: unknown mode %d: %w", p.cfg.Mode, ErrNoCredentials)
}

// appliesTo returns true when the configured Hosts list permits host
// (case-insensitive). Empty Hosts list defers to a heuristic — any
// host whose name contains "artifactory".
func (p *ArtifactoryProvider) appliesTo(host string) bool {
	host = strings.ToLower(host)
	if len(p.cfg.Hosts) == 0 {
		return hostLooksLikeArtifactory(host)
	}
	for _, h := range p.cfg.Hosts {
		if strings.EqualFold(strings.TrimSpace(h), host) {
			return true
		}
	}
	return false
}

// hostLooksLikeArtifactory is the conservative heuristic used when no
// explicit Hosts list narrows the provider. It avoids responding to
// every host (which would shadow other providers).
func hostLooksLikeArtifactory(host string) bool {
	return strings.Contains(host, "artifactory")
}

// readEnvFallback picks the first non-empty env value across the
// supplied keys (after trimming whitespace). Empty input keys are
// skipped silently.
func readEnvFallback(get func(string) string, keys ...string) string {
	for _, k := range keys {
		if k == "" {
			continue
		}
		if v := strings.TrimSpace(get(k)); v != "" {
			return v
		}
	}
	return ""
}
