package source

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	authpkg "github.com/psyf8t/astinus/internal/image/auth"
)

// registrySource pulls images from an OCI distribution registry via
// go-containerregistry.
//
// The image is fetched lazily on Image() so the factory can hand back
// a source object before any network I/O happens — the caller
// controls when the pull starts via the request context.
type registrySource struct {
	ref     name.Reference
	opts    Options
	once    sync.Once
	image   v1.Image
	loadErr error
}

// newRegistrySource validates ref and returns a source that will pull
// from it on the first Image() call.
func newRegistrySource(ref string, opts Options) (*registrySource, error) {
	parseOpts := []name.Option{}
	if opts.Insecure {
		parseOpts = append(parseOpts, name.Insecure)
	}
	parsed, err := name.ParseReference(ref, parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("registry: parse %q: %w", ref, err)
	}
	return &registrySource{ref: parsed, opts: opts}, nil
}

// Reference implements ImageSource.
func (r *registrySource) Reference() name.Reference { return r.ref }

// Image implements ImageSource. Performs the remote pull on first call
// and caches the result for subsequent calls.
func (r *registrySource) Image(ctx context.Context) (v1.Image, error) {
	r.once.Do(func() {
		r.image, r.loadErr = r.pull(ctx)
	})
	return r.image, r.loadErr
}

// Close implements ImageSource. No persistent resources to release —
// the v1.Image holds at most a HTTP client which the GC reaps.
func (r *registrySource) Close() error { return nil }

// pull does the actual network fetch using whatever transport and
// credentials Options provided.
func (r *registrySource) pull(ctx context.Context) (v1.Image, error) {
	remoteOpts := []remote.Option{remote.WithContext(ctx)}

	if r.opts.Transport != nil {
		remoteOpts = append(remoteOpts, remote.WithTransport(r.opts.Transport))
	}
	if r.opts.Platform != "" {
		platform, err := v1.ParsePlatform(r.opts.Platform)
		if err != nil {
			return nil, fmt.Errorf("registry: parse platform %q: %w", r.opts.Platform, err)
		}
		remoteOpts = append(remoteOpts, remote.WithPlatform(*platform))
	}
	if r.opts.Credentials != nil {
		auth, err := resolveAuth(ctx, r.opts.Credentials, r.ref.Context().RegistryStr())
		if err != nil {
			return nil, err
		}
		remoteOpts = append(remoteOpts, remote.WithAuth(auth))
	}

	img, err := remote.Image(r.ref, remoteOpts...)
	if err != nil {
		return nil, mapRemoteError(err, r.ref.String())
	}
	return img, nil
}

// resolveAuth queries the credential provider and adapts the result
// to authn.Authenticator. ErrNoCredentials becomes anonymous auth.
func resolveAuth(ctx context.Context, provider authpkg.CredentialProvider, host string) (authn.Authenticator, error) {
	creds, err := provider.Resolve(ctx, host)
	if err != nil {
		if errors.Is(err, authpkg.ErrNoCredentials) {
			return authn.Anonymous, nil
		}
		return nil, fmt.Errorf("registry: credential provider %q: %w", provider.Name(), err)
	}
	return &authn.Basic{Username: creds.Username, Password: pickPassword(creds)}, nil
}

// pickPassword chooses the right "password" field for go-cr's basic
// authenticator. Bearer tokens take precedence over identity tokens
// over plain passwords.
func pickPassword(c authpkg.Credentials) string {
	switch {
	case c.Token != "":
		return c.Token
	case c.IdentityToken != "":
		return c.IdentityToken
	default:
		return c.Password
	}
}

// mapRemoteError converts go-containerregistry transport errors into
// the source package's sentinel set (currently just ErrNotFound) so
// callers can `errors.Is` them. Anything we don't recognise wraps
// untouched.
func mapRemoteError(err error, ref string) error {
	var te *transport.Error
	if errors.As(err, &te) {
		if te.StatusCode == http.StatusNotFound {
			return fmt.Errorf("registry: pull %q: %w", ref, ErrNotFound)
		}
		// Embed the registry's response body in the message so
		// users see the real reason without having to enable debug
		// logging.
		return fmt.Errorf("registry: pull %q: %d %s: %s",
			ref, te.StatusCode, http.StatusText(te.StatusCode), strings.TrimSpace(te.Error()))
	}
	return fmt.Errorf("registry: pull %q: %w", ref, err)
}
