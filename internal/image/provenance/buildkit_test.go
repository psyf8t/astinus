package provenance

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// ─── Extract ──────────────────────────────────────────────────────────────

func TestExtractNilImage(t *testing.T) {
	got, err := Extract(nil)
	if !errors.Is(err, ErrNoProvenance) {
		t.Fatalf("err = %v, want ErrNoProvenance", err)
	}
	if got != nil {
		t.Errorf("got = %+v, want nil", got)
	}
}

func TestExtractRegularImageReturnsNoProvenance(t *testing.T) {
	// empty.Image's config blob is a real OCI ConfigFile, not an
	// in-toto statement. Extract must surface ErrNoProvenance.
	got, err := Extract(empty.Image)
	if !errors.Is(err, ErrNoProvenance) {
		t.Fatalf("err = %v, want ErrNoProvenance", err)
	}
	if got != nil {
		t.Errorf("got = %+v, want nil for non-attestation image", got)
	}
}

func TestExtractParsesSLSAv02(t *testing.T) {
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": slsaPredicateTypeV02,
		"subject": []map[string]any{
			{
				"name": "pkg:docker/library/myapp@sha256:abc",
				"digest": map[string]string{
					"sha256": "abc",
				},
			},
		},
		"predicate": map[string]any{
			"builder":   map[string]string{"id": "https://github.com/docker/buildkit@v0.13.0"},
			"buildType": "https://mobyproject.org/buildkit@v1",
			"invocation": map[string]any{
				"configSource": map[string]string{"uri": "git+https://github.com/example/myapp"},
			},
			"materials": []map[string]any{
				{
					"uri":    "git+https://github.com/example/myapp",
					"digest": map[string]string{"sha1": "deadbeef"},
				},
				{
					"uri":    "pkg:docker/library/alpine@sha256:111",
					"digest": map[string]string{"sha256": "111"},
				},
			},
			"metadata": map[string]any{
				"buildStartedOn":  "2026-05-03T10:00:00Z",
				"buildFinishedOn": "2026-05-03T10:01:23Z",
			},
		},
	}
	body, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}

	img := withRawConfig(t, body)

	got, err := Extract(img)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if got == nil {
		t.Fatal("Extract returned nil for a valid in-toto statement")
	}
	if got.PredicateType != slsaPredicateTypeV02 {
		t.Errorf("PredicateType = %q", got.PredicateType)
	}
	if got.Builder.ID != "https://github.com/docker/buildkit@v0.13.0" {
		t.Errorf("Builder.ID = %q", got.Builder.ID)
	}
	if got.Builder.Version != "v0.13.0" {
		t.Errorf("Builder.Version = %q, want v0.13.0", got.Builder.Version)
	}
	if got.BuildType != "https://mobyproject.org/buildkit@v1" {
		t.Errorf("BuildType = %q", got.BuildType)
	}
	if len(got.Materials) != 2 {
		t.Errorf("len(Materials) = %d, want 2", len(got.Materials))
	}
	if got.Materials[0].Digest["sha1"] != "deadbeef" {
		t.Errorf("Materials[0].Digest[sha1] = %q", got.Materials[0].Digest["sha1"])
	}
	if got.StartedOn.IsZero() || got.FinishedOn.IsZero() {
		t.Errorf("Started/Finished are zero: %v / %v", got.StartedOn, got.FinishedOn)
	}
}

func TestExtractUnknownPredicateTypeKeepsType(t *testing.T) {
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://example.com/custom/v1",
		"subject":       []map[string]any{{"name": "x", "digest": map[string]string{"sha256": "x"}}},
		"predicate":     map[string]any{},
	}
	body, _ := json.Marshal(stmt)
	img := withRawConfig(t, body)

	got, err := Extract(img)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if got == nil {
		t.Fatal("Extract returned nil for unknown predicate type")
	}
	if got.PredicateType != "https://example.com/custom/v1" {
		t.Errorf("PredicateType = %q", got.PredicateType)
	}
	if len(got.Materials) != 0 {
		t.Errorf("Materials = %+v, want empty for unknown predicate", got.Materials)
	}
}

func TestExtractRejectsBadSLSAPredicate(t *testing.T) {
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": slsaPredicateTypeV02,
		"subject":       []map[string]any{{"name": "x", "digest": map[string]string{"sha256": "x"}}},
		"predicate":     "not an object", // wrong shape
	}
	body, _ := json.Marshal(stmt)
	img := withRawConfig(t, body)

	if _, err := Extract(img); err == nil {
		t.Fatal("expected error for malformed SLSA predicate, got nil")
	}
}

// ─── FindAttestation ──────────────────────────────────────────────────────

func TestFindAttestationNilIndex(t *testing.T) {
	got, err := FindAttestation(nil, v1.Hash{})
	if !errors.Is(err, ErrNoProvenance) {
		t.Fatalf("err = %v, want ErrNoProvenance", err)
	}
	if got != nil {
		t.Errorf("got = %v", got)
	}
}

func TestFindAttestationNoMatch(t *testing.T) {
	platform := mustImage(t)
	platformDigest := mustDigest(t, platform)

	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add: platform,
	})

	// Querying for the platform digest should NOT match it (the
	// platform image isn't an attestation manifest).
	got, err := FindAttestation(idx, platformDigest)
	if !errors.Is(err, ErrNoProvenance) {
		t.Fatalf("err = %v, want ErrNoProvenance", err)
	}
	if got != nil {
		t.Errorf("got = %v, want nil", got)
	}
}

func TestFindAttestationFindsMatch(t *testing.T) {
	platform := mustImage(t)
	platformDigest := mustDigest(t, platform)

	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": slsaPredicateTypeV02,
		"subject":       []map[string]any{{"name": "x", "digest": map[string]string{"sha256": "x"}}},
		"predicate":     map[string]any{},
	}
	body, _ := json.Marshal(stmt)
	attestation := withRawConfig(t, body)

	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: platform},
		mutate.IndexAddendum{
			Add: attestation,
			Descriptor: v1.Descriptor{
				Annotations: map[string]string{
					annotationReferenceType:   referenceTypeAttestation,
					annotationReferenceDigest: platformDigest.String(),
				},
			},
		},
	)

	got, err := FindAttestation(idx, platformDigest)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got == nil {
		t.Fatal("expected to find attestation manifest")
	}

	// Round-trip through Extract.
	prov, err := Extract(got)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if prov == nil || prov.PredicateType != slsaPredicateTypeV02 {
		t.Errorf("provenance not extracted: %+v", prov)
	}
}

// ─── parseBuilderVersion ─────────────────────────────────────────────────

func TestParseBuilderVersion(t *testing.T) {
	cases := map[string]string{
		"https://github.com/docker/buildkit@v0.13.0": "v0.13.0",
		"https://example.com/builder@1.2.3":          "1.2.3",
		"https://example.com/builder":                "",
		"https://example.com/builder@":               "",
		"":                                           "",
	}
	for in, want := range cases {
		if got := parseBuilderVersion(in); got != want {
			t.Errorf("parseBuilderVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────

// withRawConfig builds a tiny v1.Image whose RawConfigFile bytes are
// the supplied blob. The image's other plumbing (layers, manifest)
// is borrowed from empty.Image and is not exercised by the
// provenance code under test.
func withRawConfig(t *testing.T, raw []byte) v1.Image {
	t.Helper()
	return &rawConfigImage{Image: empty.Image, raw: raw}
}

type rawConfigImage struct {
	v1.Image
	raw []byte
}

func (r *rawConfigImage) RawConfigFile() ([]byte, error) {
	return io.ReadAll(bytes.NewReader(r.raw))
}

func (r *rawConfigImage) MediaType() (types.MediaType, error) { return types.OCIManifestSchema1, nil }

// Ensure rawConfigImage still satisfies v1.Image — partial.UncompressedToImage
// stamps it via the embedded interface above; this assertion is purely a
// compile-time check.
var _ partial.WithRawConfigFile = (*rawConfigImage)(nil)

// mustImage builds a small random image for tests that need a
// platform image to point at.
func mustImage(t *testing.T) v1.Image {
	t.Helper()
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	return img
}

func mustDigest(t *testing.T, img v1.Image) v1.Hash {
	t.Helper()
	d, err := img.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	return d
}
