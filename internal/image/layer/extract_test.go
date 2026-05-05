package layer

import (
	"context"
	"errors"
	"io"
	"sort"
	"testing"
)

func TestWalkFilesDeliversAllVisibleFiles(t *testing.T) {
	img := buildImage(t, []layerSpec{
		{files: map[string]string{"a": "1", "etc/hostname": "h"}},
		{files: map[string]string{"b": "2"}},
	})

	var got []string
	err := WalkFiles(context.Background(), img, func(_ context.Context, e FileEntry, body io.Reader) error {
		buf, _ := io.ReadAll(body)
		got = append(got, e.Path+"="+string(buf))
		return nil
	})
	if err != nil {
		t.Fatalf("WalkFiles: %v", err)
	}
	sort.Strings(got)
	want := []string{"a=1", "b=2", "etc/hostname=h"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("entry %d = %q, want %q", i, got[i], w)
		}
	}
}

func TestWalkFilesEmitsLatestLayerContents(t *testing.T) {
	img := buildImage(t, []layerSpec{
		{files: map[string]string{"foo": "v1"}},
		{files: map[string]string{"foo": "v2"}},
	})
	var got string
	err := WalkFiles(context.Background(), img, func(_ context.Context, e FileEntry, body io.Reader) error {
		if e.Path == "foo" {
			b, _ := io.ReadAll(body)
			got = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkFiles: %v", err)
	}
	if got != "v2" {
		t.Errorf("foo body = %q, want v2 (latest layer)", got)
	}
}

func TestWalkFilesSkipsWhiteoutFiles(t *testing.T) {
	img := buildImage(t, []layerSpec{
		{files: map[string]string{"a": "1", "b": "2"}},
		{whiteouts: []string{"a"}},
	})
	var paths []string
	err := WalkFiles(context.Background(), img, func(_ context.Context, e FileEntry, _ io.Reader) error {
		paths = append(paths, e.Path)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkFiles: %v", err)
	}
	sort.Strings(paths)
	if len(paths) != 1 || paths[0] != "b" {
		t.Errorf("paths = %v, want [b]", paths)
	}
}

func TestWalkFilesSkipFileSentinel(t *testing.T) {
	img := buildImage(t, []layerSpec{
		{files: map[string]string{"a": "1", "b": "2"}},
	})
	var visited []string
	err := WalkFiles(context.Background(), img, func(_ context.Context, e FileEntry, _ io.Reader) error {
		if e.Path == "a" {
			return SkipFile
		}
		visited = append(visited, e.Path)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkFiles: %v", err)
	}
	if len(visited) != 1 || visited[0] != "b" {
		t.Errorf("visited = %v, want [b]", visited)
	}
}

func TestWalkFilesPropagatesError(t *testing.T) {
	img := buildImage(t, []layerSpec{
		{files: map[string]string{"a": "1"}},
	})
	want := errors.New("kaboom")
	err := WalkFiles(context.Background(), img, func(_ context.Context, _ FileEntry, _ io.Reader) error {
		return want
	})
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("err = %v, want wraps %v", err, want)
	}
}

func TestWalkFilesNilArgs(t *testing.T) {
	if err := WalkFiles(context.Background(), nil, func(context.Context, FileEntry, io.Reader) error { return nil }); err == nil {
		t.Error("expected error for nil image")
	}
	img := buildImage(t, nil)
	if err := WalkFiles(context.Background(), img, nil); err == nil {
		t.Error("expected error for nil visitor")
	}
}

func TestWalkFilesContextCanceled(t *testing.T) {
	img := buildImage(t, []layerSpec{
		{files: map[string]string{"a": "1"}},
		{files: map[string]string{"b": "2"}},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WalkFiles(ctx, img, func(context.Context, FileEntry, io.Reader) error { return nil }); err == nil {
		t.Error("expected context cancellation error")
	}
}
