package source

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFromReferenceEmpty(t *testing.T) {
	if _, err := FromReference(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty reference")
	}
}

func TestFromReferenceUnsupportedSchemes(t *testing.T) {
	cases := []string{
		"oci://./layout",
		"docker-daemon://nginx:latest",
		"podman-daemon://nginx:latest",
	}
	for _, ref := range cases {
		t.Run(ref, func(t *testing.T) {
			_, err := FromReference(context.Background(), ref)
			if !errors.Is(err, ErrUnsupportedScheme) {
				t.Fatalf("err = %v, want ErrUnsupportedScheme", err)
			}
		})
	}
}

func TestFromReferenceUnknownScheme(t *testing.T) {
	_, err := FromReference(context.Background(), "myproto://anything")
	if !errors.Is(err, ErrUnsupportedScheme) {
		t.Fatalf("err = %v, want ErrUnsupportedScheme", err)
	}
}

func TestFromReferenceArchiveSchemeMissingFile(t *testing.T) {
	_, err := FromReference(context.Background(), "archive:///no/such/image.tar")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestFromReferenceAutoDetectArchive(t *testing.T) {
	// Any regular file is treated as a tar; the archive source is
	// returned without parsing the bytes.
	dir := t.TempDir()
	path := filepath.Join(dir, "image.tar")
	if err := os.WriteFile(path, []byte("not a real tar"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	src, err := FromReference(context.Background(), path)
	if err != nil {
		t.Fatalf("FromReference: %v", err)
	}
	defer src.Close()
	if _, ok := src.(*archiveSource); !ok {
		t.Errorf("source = %T, want *archiveSource", src)
	}
}

func TestFromReferenceAutoDetectRegistry(t *testing.T) {
	src, err := FromReference(context.Background(), "ghcr.io/foo/bar:latest")
	if err != nil {
		t.Fatalf("FromReference: %v", err)
	}
	defer src.Close()
	if _, ok := src.(*registrySource); !ok {
		t.Errorf("source = %T, want *registrySource", src)
	}
	if got := src.Reference().String(); got != "ghcr.io/foo/bar:latest" {
		t.Errorf("Reference = %q", got)
	}
}

func TestFromReferenceDirectoryNotOCILayout(t *testing.T) {
	dir := t.TempDir()
	_, err := FromReference(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for plain directory")
	}
}

func TestFromReferenceOCILayoutDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"index.json", "oci-layout"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := FromReference(context.Background(), dir)
	if !errors.Is(err, ErrUnsupportedScheme) {
		t.Fatalf("err = %v, want ErrUnsupportedScheme (OCI layout planned for Stage 8)", err)
	}
}

func TestSplitScheme(t *testing.T) {
	cases := []struct {
		in     string
		scheme string
		body   string
		ok     bool
	}{
		{"docker-daemon://x", "docker-daemon", "x", true},
		{"archive:///path", "archive", "/path", true},
		{"myproto://body", "myproto", "body", true},
		{"ghcr.io/foo:latest", "", "", false},
		{"://no-scheme", "", "", false},
		{"PROTO://upper", "", "", false}, // schemes are lowercase only
	}
	for _, c := range cases {
		s, b, ok := splitScheme(c.in)
		if s != c.scheme || b != c.body || ok != c.ok {
			t.Errorf("splitScheme(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.in, s, b, ok, c.scheme, c.body, c.ok)
		}
	}
}
