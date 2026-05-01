package auth

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// EnvProvider reads credentials from process environment.
//
// Two flavors are supported:
//
//   - Generic: REGISTRY_USERNAME / REGISTRY_PASSWORD or REGISTRY_TOKEN.
//     Applied to every host — useful for single-registry CI jobs.
//   - Per-host: ASTINUS_REGISTRY_<HOST>_USERNAME /
//     ASTINUS_REGISTRY_<HOST>_PASSWORD / ASTINUS_REGISTRY_<HOST>_TOKEN
//     where <HOST> is the host with `.` and `-` replaced by `_` and
//     uppercased (e.g. `ghcr_io`, `artifactory_corp_com`).
//     Per-host wins over generic when both apply.
type EnvProvider struct {
	// getenv defaults to os.Getenv; tests override it.
	getenv func(string) string
}

// NewEnvProvider returns an EnvProvider that reads from the live
// process environment.
func NewEnvProvider() *EnvProvider {
	return &EnvProvider{getenv: os.Getenv}
}

// Name implements CredentialProvider.
func (e *EnvProvider) Name() string { return "env" }

// Resolve implements CredentialProvider.
func (e *EnvProvider) Resolve(_ context.Context, host string) (Credentials, error) {
	get := e.getenv
	if get == nil {
		get = os.Getenv
	}

	hostKey := envHostKey(host)

	// Per-host wins.
	user := get("ASTINUS_REGISTRY_" + hostKey + "_USERNAME")
	pass := get("ASTINUS_REGISTRY_" + hostKey + "_PASSWORD")
	token := get("ASTINUS_REGISTRY_" + hostKey + "_TOKEN")

	// Generic fallback.
	if user == "" {
		user = get("REGISTRY_USERNAME")
	}
	if pass == "" {
		pass = get("REGISTRY_PASSWORD")
	}
	if token == "" {
		token = get("REGISTRY_TOKEN")
	}

	creds := Credentials{Username: user, Password: pass, Token: token}
	if creds.IsEmpty() {
		return Credentials{}, fmt.Errorf("env: no credentials for %q: %w", host, ErrNoCredentials)
	}
	return creds, nil
}

// envHostKey normalises a host into the suffix we look for in env
// variable names. "ghcr.io" -> "GHCR_IO".
func envHostKey(host string) string {
	r := strings.NewReplacer(".", "_", "-", "_", ":", "_")
	return strings.ToUpper(r.Replace(host))
}
