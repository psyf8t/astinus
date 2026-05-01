package source

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	authpkg "github.com/psyf8t/astinus/internal/image/auth"
)

// startInMemoryRegistry spins up an in-memory OCI registry on a random
// port and returns the host (without scheme) plus a teardown.
func startInMemoryRegistry(t *testing.T) (string, func()) {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	u, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatalf("parse server URL: %v", err)
	}
	return u.Host, srv.Close
}

func pushImage(t *testing.T, host string, ref string, img v1.Image) {
	t.Helper()
	tag, err := name.NewTag(host+"/"+ref, name.Insecure)
	if err != nil {
		t.Fatalf("NewTag: %v", err)
	}
	if err := remote.Write(tag, img); err != nil {
		t.Fatalf("remote.Write: %v", err)
	}
}

func TestRegistrySourcePullAnonymous(t *testing.T) {
	host, stop := startInMemoryRegistry(t)
	defer stop()

	img := mustRandomImage(t, 256, 1)
	pushImage(t, host, "foo/bar:v1", img)

	src, err := newRegistrySource(host+"/foo/bar:v1", Options{Insecure: true})
	if err != nil {
		t.Fatalf("newRegistrySource: %v", err)
	}
	defer src.Close()

	loaded, err := src.Image(context.Background())
	if err != nil {
		t.Fatalf("Image: %v", err)
	}
	if _, err := loaded.Manifest(); err != nil {
		t.Errorf("Manifest: %v", err)
	}
}

func TestRegistrySourcePullCachesOnSecondCall(t *testing.T) {
	host, stop := startInMemoryRegistry(t)
	defer stop()
	pushImage(t, host, "foo/bar:v1", mustRandomImage(t, 64, 1))

	src, err := newRegistrySource(host+"/foo/bar:v1", Options{Insecure: true})
	if err != nil {
		t.Fatalf("newRegistrySource: %v", err)
	}
	defer src.Close()

	first, err := src.Image(context.Background())
	if err != nil {
		t.Fatalf("first Image: %v", err)
	}
	second, err := src.Image(context.Background())
	if err != nil {
		t.Fatalf("second Image: %v", err)
	}
	if first != second {
		t.Errorf("Image() did not cache: %p vs %p", first, second)
	}
}

func TestRegistrySourceNotFoundMapsErr(t *testing.T) {
	host, stop := startInMemoryRegistry(t)
	defer stop()

	src, err := newRegistrySource(host+"/no/such:tag", Options{Insecure: true})
	if err != nil {
		t.Fatalf("newRegistrySource: %v", err)
	}
	defer src.Close()

	_, err = src.Image(context.Background())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want wrap of ErrNotFound", err)
	}
}

func TestRegistrySourceParsesPlatform(t *testing.T) {
	host, stop := startInMemoryRegistry(t)
	defer stop()
	pushImage(t, host, "foo/bar:v1", mustRandomImage(t, 64, 1))

	src, err := newRegistrySource(host+"/foo/bar:v1", Options{
		Insecure: true,
		Platform: "linux/arm64",
	})
	if err != nil {
		t.Fatalf("newRegistrySource: %v", err)
	}
	defer src.Close()
	if _, err := src.Image(context.Background()); err != nil {
		t.Fatalf("Image with platform: %v", err)
	}
}

func TestRegistrySourceParseFailure(t *testing.T) {
	if _, err := newRegistrySource(":::not a ref", Options{}); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestPickPasswordPrecedence(t *testing.T) {
	cases := []struct {
		name string
		c    authpkg.Credentials
		want string
	}{
		{"token wins", authpkg.Credentials{Password: "p", Token: "t", IdentityToken: "i"}, "t"},
		{"identity wins over password", authpkg.Credentials{Password: "p", IdentityToken: "i"}, "i"},
		{"plain password", authpkg.Credentials{Password: "p"}, "p"},
		{"none", authpkg.Credentials{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pickPassword(tc.c); got != tc.want {
				t.Errorf("pickPassword = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveAuthAnonymousOnNoCreds(t *testing.T) {
	provider := stubProvider{name: "stub", err: authpkg.ErrNoCredentials}
	a, err := resolveAuth(context.Background(), &provider, "any.host")
	if err != nil {
		t.Fatalf("resolveAuth: %v", err)
	}
	if a == nil {
		t.Fatal("expected an authenticator (anonymous)")
	}
}

type stubProvider struct {
	name string
	c    authpkg.Credentials
	err  error
}

func (s *stubProvider) Name() string { return s.name }
func (s *stubProvider) Resolve(_ context.Context, _ string) (authpkg.Credentials, error) {
	return s.c, s.err
}
