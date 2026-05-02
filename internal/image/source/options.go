package source

import (
	"log/slog"
	"net/http"

	"github.com/psyf8t/astinus/internal/image/auth"
)

// Options configures Factory and the sources it produces.
type Options struct {
	// Transport is the http.RoundTripper used for registry traffic.
	// Nil means "use http.DefaultTransport" — fine for tests, not
	// recommended in production (no CA / proxy / retry).
	Transport http.RoundTripper

	// Credentials is the chain queried for registry auth. Nil means
	// "anonymous only".
	Credentials auth.CredentialProvider

	// Platform restricts multi-arch manifest resolution. Empty
	// string means "the runtime's default platform" (linux/amd64
	// on most CI; the host arch on dev machines). Format is the
	// usual "os/arch" pair (e.g. "linux/arm64").
	Platform string

	// Insecure permits HTTP (not HTTPS) connections to the registry.
	// This is independent of TLS verification (which is configured
	// on Transport).
	Insecure bool

	// Logger receives auto-detection trace records (debug-level for
	// each probe attempt, info-level when a source is selected). Nil
	// means slog.Default(), so the package always has a usable
	// destination.
	Logger *slog.Logger

	// daemonProber is the seam used by autoDetect to decide whether
	// the local Docker / Podman daemon owns ref. Unexported because
	// only tests inject a fake; production always uses the real
	// pkg/v1/daemon-backed prober.
	daemonProber daemonProber
}

// Option mutates Options. Used by FromReference and friends to keep
// the call site readable.
type Option func(*Options)

// WithTransport sets Options.Transport.
func WithTransport(rt http.RoundTripper) Option {
	return func(o *Options) { o.Transport = rt }
}

// WithCredentials sets Options.Credentials.
func WithCredentials(p auth.CredentialProvider) Option {
	return func(o *Options) { o.Credentials = p }
}

// WithPlatform sets Options.Platform (e.g. "linux/arm64").
func WithPlatform(p string) Option {
	return func(o *Options) { o.Platform = p }
}

// WithInsecure permits HTTP access to the registry.
func WithInsecure(v bool) Option {
	return func(o *Options) { o.Insecure = v }
}

// WithLogger sets Options.Logger. The factory uses it for
// auto-detection trace records; the source implementations themselves
// do not log (the caller's pipeline already wraps them).
func WithLogger(l *slog.Logger) Option {
	return func(o *Options) { o.Logger = l }
}

// withDaemonProber injects a fake prober. Test-only; not exported.
func withDaemonProber(p daemonProber) Option {
	return func(o *Options) { o.daemonProber = p }
}

func applyOptions(opts []Option) Options {
	o := Options{}
	for _, fn := range opts {
		fn(&o)
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.daemonProber == nil {
		o.daemonProber = realDaemonProber{}
	}
	return o
}
