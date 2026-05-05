package lifecycle

import (
	"context"
	"errors"
	"testing"
)

// fakeSource is a configurable Source for resolver tests.
type fakeSource struct {
	name   string
	online bool
	calls  int
	lc     *Lifecycle
	err    error
}

func (f *fakeSource) Name() string          { return f.name }
func (f *fakeSource) RequiresNetwork() bool { return f.online }
func (f *fakeSource) Fetch(_ context.Context, _, _ string) (*Lifecycle, error) {
	f.calls++
	return f.lc, f.err
}

func TestResolver_HybridFallsBackOnNotFound(t *testing.T) {
	online := &fakeSource{name: "online", online: true, err: ErrNotFound}
	bundled := &fakeSource{name: "bundled", online: false,
		lc: &Lifecycle{Cycle: "20"}}
	r := NewResolver(ResolverOptions{
		Online: online, Bundled: bundled, Mode: ModeHybrid,
	})
	lc, src, err := r.Resolve(context.Background(), "nodejs", "20")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if lc == nil || lc.Cycle != "20" || src != "bundled" {
		t.Errorf("got (%+v, %q) — want bundled fallback hit", lc, src)
	}
	if online.calls != 1 || bundled.calls != 1 {
		t.Errorf("expected both called once each (online=%d bundled=%d)",
			online.calls, bundled.calls)
	}
}

func TestResolver_OnlineModeSkipsBundled(t *testing.T) {
	online := &fakeSource{name: "online", online: true, err: ErrNotFound}
	bundled := &fakeSource{name: "bundled",
		lc: &Lifecycle{Cycle: "20"}}
	r := NewResolver(ResolverOptions{
		Online: online, Bundled: bundled, Mode: ModeOnline,
	})
	_, _, err := r.Resolve(context.Background(), "nodejs", "20")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	if bundled.calls != 0 {
		t.Errorf("bundled called %d times under online mode", bundled.calls)
	}
}

func TestResolver_OfflineModeSkipsOnline(t *testing.T) {
	online := &fakeSource{name: "online", online: true,
		lc: &Lifecycle{Cycle: "online"}}
	bundled := &fakeSource{name: "bundled",
		lc: &Lifecycle{Cycle: "bundled"}}
	r := NewResolver(ResolverOptions{
		Online: online, Bundled: bundled, Mode: ModeOffline,
	})
	lc, src, err := r.Resolve(context.Background(), "x", "1")
	if err != nil {
		t.Fatal(err)
	}
	if lc.Cycle != "bundled" || src != "bundled" {
		t.Errorf("got (%+v, %q), want bundled", lc, src)
	}
	if online.calls != 0 {
		t.Errorf("online called %d times under offline mode", online.calls)
	}
}

func TestResolver_TransientPropagates(t *testing.T) {
	online := &fakeSource{name: "online", online: true, err: ErrTransient}
	r := NewResolver(ResolverOptions{
		Online: online, Mode: ModeOnline,
	})
	_, _, err := r.Resolve(context.Background(), "x", "1")
	if !errors.Is(err, ErrTransient) {
		t.Errorf("err = %v, want ErrTransient", err)
	}
}

func TestResolver_HybridSucceedsOnOnline(t *testing.T) {
	online := &fakeSource{name: "endoflife.date", online: true,
		lc: &Lifecycle{Cycle: "20"}}
	bundled := &fakeSource{name: "bundled",
		lc: &Lifecycle{Cycle: "bundled-fallback"}}
	r := NewResolver(ResolverOptions{
		Online: online, Bundled: bundled, Mode: ModeHybrid,
	})
	lc, src, err := r.Resolve(context.Background(), "x", "1")
	if err != nil {
		t.Fatal(err)
	}
	if lc.Cycle != "20" || src != "endoflife.date" {
		t.Errorf("hybrid mode should prefer online; got (%+v, %q)", lc, src)
	}
	if bundled.calls != 0 {
		t.Errorf("bundled called %d times when online succeeded", bundled.calls)
	}
}

func TestResolver_NilSafe(t *testing.T) {
	var r *Resolver
	_, _, err := r.Resolve(context.Background(), "x", "1")
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("nil resolver err = %v, want ErrUnsupported", err)
	}
}

func TestResolver_EmptyProduct(t *testing.T) {
	r := NewResolver(ResolverOptions{})
	_, _, err := r.Resolve(context.Background(), "", "1")
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("err = %v, want ErrUnsupported", err)
	}
}

func TestResolver_DefaultModeIsHybrid(t *testing.T) {
	r := NewResolver(ResolverOptions{})
	if r.Mode() != ModeHybrid {
		t.Errorf("Mode = %q, want hybrid (default)", r.Mode())
	}
}
