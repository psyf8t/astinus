package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Chain is a CredentialProvider composed of other providers.
//
// On Resolve, Chain queries each provider in registration order. The
// first provider that returns non-empty credentials wins. Providers
// that return ErrNoCredentials (wrapped) are skipped silently. Any
// other error halts iteration and propagates — these are
// configuration errors (malformed config files, etc.) that should not
// be swallowed.
type Chain struct {
	providers []CredentialProvider
}

// NewChain returns a Chain initialised with providers (may be empty
// or nil).
func NewChain(providers ...CredentialProvider) *Chain {
	return &Chain{providers: append([]CredentialProvider(nil), providers...)}
}

// Append adds providers to the end of the chain.
func (c *Chain) Append(providers ...CredentialProvider) {
	c.providers = append(c.providers, providers...)
}

// Providers returns the configured chain in order. The returned slice
// is a copy — mutating it does not affect the Chain.
func (c *Chain) Providers() []CredentialProvider {
	out := make([]CredentialProvider, len(c.providers))
	copy(out, c.providers)
	return out
}

// Name implements CredentialProvider.
//
// Format: "chain[env,docker-config]" — useful for logging which chain
// produced (or failed to produce) credentials.
func (c *Chain) Name() string {
	names := make([]string, len(c.providers))
	for i, p := range c.providers {
		names[i] = p.Name()
	}
	return "chain[" + strings.Join(names, ",") + "]"
}

// Resolve implements CredentialProvider.
//
// Returns the first non-empty credential set. Returns ErrNoCredentials
// (wrapped) when every provider declined.
func (c *Chain) Resolve(ctx context.Context, host string) (Credentials, error) {
	if len(c.providers) == 0 {
		return Credentials{}, fmt.Errorf("chain: empty: %w", ErrNoCredentials)
	}
	var lastNoCreds error
	for _, p := range c.providers {
		creds, err := p.Resolve(ctx, host)
		if err == nil {
			return creds, nil
		}
		if errors.Is(err, ErrNoCredentials) {
			lastNoCreds = err
			continue
		}
		return Credentials{}, fmt.Errorf("chain: provider %q: %w", p.Name(), err)
	}
	if lastNoCreds == nil {
		// Defensive: shouldn't happen — if all providers ran they
		// either succeeded or wrapped ErrNoCredentials.
		return Credentials{}, fmt.Errorf("chain: %w", ErrNoCredentials)
	}
	return Credentials{}, fmt.Errorf("chain: no provider supplied credentials for %q: %w", host, ErrNoCredentials)
}

// DefaultChain returns the chain used when the caller has no special
// requirements: env vars first, then Docker config. The order matches
// spec section 8.3 (the cloud-vendor providers added in Stage 9 will
// slot in after this default chain).
func DefaultChain() *Chain {
	return NewChain(
		NewEnvProvider(),
		NewDockerConfigProvider(),
	)
}
