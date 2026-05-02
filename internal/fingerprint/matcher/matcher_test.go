package matcher

import (
	"context"
	"errors"
	"testing"
)

func TestNullMatcherAlwaysNoMatch(t *testing.T) {
	_, err := (NullMatcher{}).Lookup(context.Background(), "sha256", "anything")
	if !errors.Is(err, ErrNoMatch) {
		t.Fatalf("err = %v, want ErrNoMatch", err)
	}
	if (NullMatcher{}).Name() != "null" {
		t.Errorf("Name = %q", (NullMatcher{}).Name())
	}
}

func TestLocalMatcher(t *testing.T) {
	m := NewLocalMatcher()
	if m.Len() != 0 {
		t.Errorf("Len = %d", m.Len())
	}
	m.Add("SHA256", "ABC", Match{Name: "jq", Version: "1.7.1"})
	if m.Len() != 1 {
		t.Errorf("Len after Add = %d", m.Len())
	}

	got, err := m.Lookup(context.Background(), "sha256", "abc")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Name != "jq" || got.Version != "1.7.1" {
		t.Errorf("got = %+v", got)
	}

	if _, err := m.Lookup(context.Background(), "sha256", "deadbeef"); !errors.Is(err, ErrNoMatch) {
		t.Errorf("Lookup miss err = %v", err)
	}
}

type stubMatcher struct {
	name string
	out  Match
	err  error
	hits int
}

func (s *stubMatcher) Name() string { return s.name }
func (s *stubMatcher) Lookup(_ context.Context, _, _ string) (Match, error) {
	s.hits++
	return s.out, s.err
}

func TestChainFirstSuccess(t *testing.T) {
	a := &stubMatcher{name: "a", err: ErrNoMatch}
	b := &stubMatcher{name: "b", out: Match{Name: "found"}}
	c := &stubMatcher{name: "c"}
	got, err := NewChain(a, b, c).Lookup(context.Background(), "sha256", "x")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Name != "found" {
		t.Errorf("got = %+v", got)
	}
	if c.hits != 0 {
		t.Errorf("c should not be queried")
	}
}

func TestChainAllNoMatch(t *testing.T) {
	a := &stubMatcher{name: "a", err: ErrNoMatch}
	b := &stubMatcher{name: "b", err: ErrNoMatch}
	if _, err := NewChain(a, b).Lookup(context.Background(), "sha256", "x"); !errors.Is(err, ErrNoMatch) {
		t.Errorf("err = %v", err)
	}
}

func TestChainHardError(t *testing.T) {
	want := errors.New("kaboom")
	a := &stubMatcher{name: "a", err: want}
	b := &stubMatcher{name: "b", out: Match{Name: "ignored"}}
	if _, err := NewChain(a, b).Lookup(context.Background(), "sha256", "x"); !errors.Is(err, want) {
		t.Errorf("err = %v, want wraps %v", err, want)
	}
	if b.hits != 0 {
		t.Errorf("b should not be queried after hard error")
	}
}
