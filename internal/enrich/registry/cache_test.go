package registry

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNoopCacheAlwaysMisses(t *testing.T) {
	c := NoopCache{}
	c.Set("x", &Metadata{Name: "x"})
	if _, ok := c.Get("x"); ok {
		t.Error("NoopCache should never report a hit")
	}
}

func TestMemoryCache_GetSetSize(t *testing.T) {
	c := NewMemoryCache()
	if _, ok := c.Get("k"); ok {
		t.Error("empty cache should miss")
	}
	c.Set("k", &Metadata{Name: "v"})
	got, ok := c.Get("k")
	if !ok || got == nil || got.Name != "v" {
		t.Errorf("Get = (%+v, %v)", got, ok)
	}
	if c.Size() != 1 {
		t.Errorf("Size = %d", c.Size())
	}
}

func TestMemoryCache_NilSafe(t *testing.T) {
	var c *MemoryCache
	if _, ok := c.Get("x"); ok {
		t.Error("nil cache should miss")
	}
	c.Set("x", &Metadata{}) // must not panic
	if c.Size() != 0 {
		t.Errorf("Size = %d", c.Size())
	}
}

func TestDiskCache_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	c, err := NewDiskCache(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}
	purl := "pkg:npm/lodash@4"
	c.Set(purl, &Metadata{Name: "lodash", Version: "4", Description: "modular utilities"})
	got, ok := c.Get(purl)
	if !ok {
		t.Fatal("disk cache miss after set")
	}
	if got.Name != "lodash" || got.Description != "modular utilities" {
		t.Errorf("got = %+v", got)
	}
}

func TestDiskCache_TTLExpiry(t *testing.T) {
	dir := t.TempDir()
	c, err := NewDiskCache(dir, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}
	purl := "pkg:npm/lodash@4"
	c.Set(purl, &Metadata{Name: "lodash"})

	// Backdate the file mtime so the TTL window is exceeded.
	path := c.pathFor(purl)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	if _, ok := c.Get(purl); ok {
		t.Error("expected expired entry to miss")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("expired entry should have been deleted")
	}
}

func TestDiskCache_CorruptEntryIsDropped(t *testing.T) {
	dir := t.TempDir()
	c, err := NewDiskCache(dir, 0)
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}
	purl := "pkg:npm/lodash@4"
	path := c.pathFor(purl)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get(purl); ok {
		t.Error("corrupt entry should miss")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("corrupt entry should have been deleted")
	}
}

func TestLayeredCache_PromotesDiskHitsToMemory(t *testing.T) {
	dir := t.TempDir()
	disk, err := NewDiskCache(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}
	mem := NewMemoryCache()
	layered := NewLayeredCache(mem, disk)

	disk.Set("p", &Metadata{Name: "v"})
	if _, ok := mem.Get("p"); ok {
		t.Error("memory should be cold before layered Get")
	}
	if _, ok := layered.Get("p"); !ok {
		t.Fatal("layered Get missed despite disk hit")
	}
	if _, ok := mem.Get("p"); !ok {
		t.Error("layered Get should promote disk hit to memory")
	}
}

func TestLayeredCache_NilSafe(t *testing.T) {
	var c *LayeredCache
	if _, ok := c.Get("x"); ok {
		t.Error("nil layered cache should miss")
	}
	c.Set("x", &Metadata{}) // must not panic
}

func TestLayeredCache_WritesPropagateToBothLayers(t *testing.T) {
	dir := t.TempDir()
	disk, err := NewDiskCache(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}
	mem := NewMemoryCache()
	c := NewLayeredCache(mem, disk)

	c.Set("p", &Metadata{Name: "v"})
	if _, ok := mem.Get("p"); !ok {
		t.Error("layered Set should hit memory")
	}
	if _, ok := disk.Get("p"); !ok {
		t.Error("layered Set should hit disk")
	}
}
