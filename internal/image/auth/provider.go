// Package auth resolves registry credentials.
//
// The package exposes one interface (CredentialProvider) and one
// composer (Chain). Built-in providers in this package handle env vars
// and Docker config — these are sufficient for personal use, public
// registries, and most CI setups. Cloud-vendor and Artifactory-specific
// providers (ECR, GCR, ACR, Artifactory tokens) land in Stage 9.
//
// Conventions:
//
//   - Resolve returns ErrNoCredentials (wrapped) when the provider has
//     no answer for the host. Chain treats that as "next provider".
//   - Other errors propagate up — they indicate misconfiguration
//     (e.g. malformed docker config.json) and the caller should not
//     silently fall through.
//   - Credentials.Token wins over Username+Password when both happen
//     to be set; the caller adapts to whichever shape the registry
//     wants.
package auth

import (
	"context"
	"errors"
)

// CredentialProvider resolves credentials for a registry host.
type CredentialProvider interface {
	// Resolve returns credentials for host (e.g. "ghcr.io",
	// "artifactory.corp.com"). Returns ErrNoCredentials (wrapped)
	// when this provider has nothing to offer for host.
	Resolve(ctx context.Context, host string) (Credentials, error)

	// Name identifies the provider in logs and Chain output.
	Name() string
}

// Credentials is the resolved credential set for one registry.
//
// Either Username+Password OR Token (bearer) will be populated; the
// caller picks whichever the registry prefers. IdentityToken is the
// OAuth2 refresh token Docker config stores; passes through to the
// transport unchanged.
type Credentials struct {
	Username      string
	Password      string
	Token         string
	IdentityToken string
}

// IsEmpty reports whether c has no usable secret material.
func (c Credentials) IsEmpty() bool {
	return c.Username == "" && c.Password == "" && c.Token == "" && c.IdentityToken == ""
}

// ErrNoCredentials is the sentinel a provider returns (wrapped, via
// fmt.Errorf("...: %w", auth.ErrNoCredentials)) when it has no answer
// for a host. Chain.Resolve uses errors.Is to skip past such
// providers.
var ErrNoCredentials = errors.New("no credentials")
