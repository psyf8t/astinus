package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DockerConfigProvider reads ~/.docker/config.json (or
// $DOCKER_CONFIG/config.json if set) — the de-facto standard
// credential store written by `docker login` and friends.
//
// Supported fields:
//   - "auths"."<host>".auth (base64 user:pass)
//   - "auths"."<host>".username / .password (already split)
//   - "auths"."<host>".identitytoken (OAuth2 refresh)
//   - "auths"."<host>".registrytoken (server-issued bearer)
//
// "credHelpers" / "credsStore" are NOT yet wired up — they require
// shelling out to a `docker-credential-<helper>` binary and are
// orthogonal to the file format. Tracked as Stage 9 follow-up.
type DockerConfigProvider struct {
	// path overrides the default discovery (env DOCKER_CONFIG or
	// ~/.docker/config.json). Empty string means "discover".
	path string
}

// NewDockerConfigProvider returns a DockerConfigProvider that
// discovers config.json via the standard precedence.
func NewDockerConfigProvider() *DockerConfigProvider {
	return &DockerConfigProvider{}
}

// NewDockerConfigProviderAt returns a provider that always reads from
// path. Useful for tests and for explicit `--registry-auth-file` flag.
func NewDockerConfigProviderAt(path string) *DockerConfigProvider {
	return &DockerConfigProvider{path: path}
}

// Name implements CredentialProvider.
func (d *DockerConfigProvider) Name() string { return "docker-config" }

// Resolve implements CredentialProvider.
func (d *DockerConfigProvider) Resolve(_ context.Context, host string) (Credentials, error) {
	path, err := d.resolvePath()
	if err != nil {
		// Missing config is "no credentials", not a hard failure.
		if errors.Is(err, fs.ErrNotExist) {
			return Credentials{}, fmt.Errorf("docker-config: %w", ErrNoCredentials)
		}
		return Credentials{}, err
	}

	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Credentials{}, fmt.Errorf("docker-config: %s: %w", path, ErrNoCredentials)
		}
		return Credentials{}, fmt.Errorf("docker-config: read %s: %w", path, err)
	}

	var cfg dockerConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return Credentials{}, fmt.Errorf("docker-config: parse %s: %w", path, err)
	}

	entry, ok := matchHost(cfg.Auths, host)
	if !ok {
		return Credentials{}, fmt.Errorf("docker-config: no entry for %q: %w", host, ErrNoCredentials)
	}

	creds, err := entry.toCredentials()
	if err != nil {
		return Credentials{}, fmt.Errorf("docker-config: %w", err)
	}
	if creds.IsEmpty() {
		return Credentials{}, fmt.Errorf("docker-config: empty entry for %q: %w", host, ErrNoCredentials)
	}
	return creds, nil
}

// resolvePath returns the file path the provider should read from.
// Precedence (matches docker CLI):
//  1. explicit DockerConfigProvider.path
//  2. $DOCKER_CONFIG/config.json
//  3. ~/.docker/config.json
func (d *DockerConfigProvider) resolvePath() (string, error) {
	if d.path != "" {
		return d.path, nil
	}
	if env := os.Getenv("DOCKER_CONFIG"); env != "" {
		return filepath.Join(env, "config.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("docker-config: home dir: %w", err)
	}
	return filepath.Join(home, ".docker", "config.json"), nil
}

// dockerConfig is the minimal shape we read out of config.json.
type dockerConfig struct {
	Auths map[string]dockerAuthEntry `json:"auths"`
}

// dockerAuthEntry is one auth record. All fields optional.
type dockerAuthEntry struct {
	Auth          string `json:"auth"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	IdentityToken string `json:"identitytoken"`
	RegistryToken string `json:"registrytoken"`
}

// toCredentials decodes an entry into our Credentials type. The
// `auth` field is a base64-encoded "user:pass"; if it's set it
// supersedes username/password.
func (e dockerAuthEntry) toCredentials() (Credentials, error) {
	c := Credentials{
		Username:      e.Username,
		Password:      e.Password,
		Token:         e.RegistryToken,
		IdentityToken: e.IdentityToken,
	}
	if e.Auth != "" {
		raw, err := base64.StdEncoding.DecodeString(e.Auth)
		if err != nil {
			return Credentials{}, fmt.Errorf("invalid base64 in auth field: %w", err)
		}
		idx := strings.IndexByte(string(raw), ':')
		if idx < 0 {
			return Credentials{}, fmt.Errorf("auth field not in user:pass form")
		}
		c.Username = string(raw[:idx])
		c.Password = string(raw[idx+1:])
	}
	return c, nil
}

// matchHost finds the auth entry whose key matches host.
//
// Docker stores hosts in a few historical shapes:
//   - exactly the host: "ghcr.io"
//   - host with scheme: "https://ghcr.io" or "https://index.docker.io/v1/"
//
// We compare the host portion after stripping any scheme and trailing
// path. Docker Hub's "https://index.docker.io/v1/" is recognised as
// matching the host "index.docker.io".
func matchHost(auths map[string]dockerAuthEntry, host string) (dockerAuthEntry, bool) {
	if entry, ok := auths[host]; ok {
		return entry, true
	}
	for key, entry := range auths {
		if normalizeAuthKey(key) == host {
			return entry, true
		}
	}
	return dockerAuthEntry{}, false
}

// normalizeAuthKey turns a docker auth-key into a bare host string.
func normalizeAuthKey(key string) string {
	s := key
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}
