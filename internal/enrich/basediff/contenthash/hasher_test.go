package contenthash

import (
	"bytes"
	"errors"
	"runtime"
	"strings"
	"testing"
)

func TestHashStreamEmpty(t *testing.T) {
	h, n, err := HashStream(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}
	// SHA-256("") is the well-known constant.
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if h != want {
		t.Errorf("hash = %q, want %q", h, want)
	}
}

func TestHashStreamKnownValue(t *testing.T) {
	h, n, err := HashStream(strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5", n)
	}
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if h != want {
		t.Errorf("hash = %q, want %q", h, want)
	}
}

func TestHashStreamLargeInputConstantMemory(t *testing.T) {
	// 16 MiB of zeros — small enough to keep tests fast, large enough
	// that any allocate-the-whole-thing implementation would show up
	// as a 16 MiB delta in heap stats.
	const size = 16 << 20
	rdr := bytes.NewReader(make([]byte, size))

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	_, n, err := HashStream(rdr)

	runtime.GC()
	runtime.ReadMemStats(&after)

	if err != nil {
		t.Fatal(err)
	}
	if n != size {
		t.Errorf("n = %d, want %d", n, size)
	}
	// io.Copy uses a 32 KiB buffer plus SHA-256 state; a healthy
	// upper bound is 1 MiB of churn (the underlying bytes.Reader
	// shows up in HeapAlloc too). We just want to catch a regression
	// that allocated O(input).
	delta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if delta > 1<<20 {
		t.Errorf("heap delta = %d bytes, want < 1 MiB (input was %d bytes)", delta, size)
	}
}

func TestHashStreamPropagatesError(t *testing.T) {
	want := errors.New("boom")
	_, _, err := HashStream(failingReader{err: want})
	if !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
}

// ─── HashCache ───────────────────────────────────────────────────────

func TestHashCacheGetSet(t *testing.T) {
	c := NewHashCache()
	k := c.Key("usr/bin/foo", 12)
	if _, ok := c.Get(k); ok {
		t.Error("empty cache should miss")
	}
	c.Set(k, "abc")
	got, ok := c.Get(k)
	if !ok || got != "abc" {
		t.Errorf("Get = (%q,%v), want (abc,true)", got, ok)
	}
}

func TestHashCacheKeyDistinguishesSize(t *testing.T) {
	c := NewHashCache()
	k1 := c.Key("foo", 10)
	k2 := c.Key("foo", 20)
	c.Set(k1, "one")
	c.Set(k2, "two")
	if v, _ := c.Get(k1); v != "one" {
		t.Errorf("k1 = %q, want one", v)
	}
	if v, _ := c.Get(k2); v != "two" {
		t.Errorf("k2 = %q, want two", v)
	}
	if c.Size() != 2 {
		t.Errorf("Size = %d, want 2", c.Size())
	}
}

func TestHashCacheNilSafe(t *testing.T) {
	var c *HashCache
	if _, ok := c.Get("x"); ok {
		t.Error("nil cache Get should be safe and miss")
	}
	c.Set("x", "y") // must not panic
	if c.Size() != 0 {
		t.Errorf("Size = %d, want 0", c.Size())
	}
}

func TestItoaTable(t *testing.T) {
	cases := map[int64]string{
		0:                "0",
		1:                "1",
		-1:               "-1",
		12345:            "12345",
		-12345:           "-12345",
		9223372036854775: "9223372036854775",
	}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q, want %q", in, got, want)
		}
	}
}

// failingReader returns an error on the first Read.
type failingReader struct{ err error }

func (f failingReader) Read(_ []byte) (int, error) { return 0, f.err }
