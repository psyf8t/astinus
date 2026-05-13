package sources

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSourceBudget_AcquireBeforeBeginStartsClock(t *testing.T) {
	b := NewSourceBudget("test", 200*time.Millisecond, 50*time.Millisecond)

	ctx, cancel, err := b.AcquireCallDeadline(context.Background())
	if err != nil {
		t.Fatalf("first acquire: unexpected err %v", err)
	}
	defer cancel()

	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("returned context has no deadline")
	}
	wait := time.Until(dl)
	if wait > 60*time.Millisecond || wait < 30*time.Millisecond {
		t.Errorf("first call deadline = %v, want roughly PerCallTimeout (50ms)", wait)
	}
}

func TestSourceBudget_TotalDurationCapsRemaining(t *testing.T) {
	b := NewSourceBudget("test", 100*time.Millisecond, 500*time.Millisecond)
	b.Begin()
	time.Sleep(60 * time.Millisecond)

	ctx, cancel, err := b.AcquireCallDeadline(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer cancel()
	dl, _ := ctx.Deadline()
	remaining := time.Until(dl)
	// Should be roughly 40ms (the remainder of the 100ms total),
	// NOT 500ms (PerCallTimeout) because remaining < PerCallTimeout.
	if remaining > 60*time.Millisecond {
		t.Errorf("acquired ctx deadline = %v, expected ≤ 60ms (remaining total)", remaining)
	}
}

func TestSourceBudget_ExhaustsAfterTotalDuration(t *testing.T) {
	b := NewSourceBudget("test", 50*time.Millisecond, 25*time.Millisecond)
	b.Begin()
	time.Sleep(75 * time.Millisecond)

	_, cancel, err := b.AcquireCallDeadline(context.Background())
	defer cancel()
	if !errors.Is(err, ErrSourceBudgetExhausted) {
		t.Errorf("acquire after total elapsed = %v, want ErrSourceBudgetExhausted", err)
	}
	if !b.IsExhausted() {
		t.Errorf("IsExhausted = false, want true after total elapsed")
	}
	if got := b.Reason(); got != "elapsed" {
		t.Errorf("Reason = %q, want elapsed", got)
	}
}

func TestSourceBudget_MarkExhausted(t *testing.T) {
	b := NewSourceBudget("test", time.Minute, 10*time.Second)
	b.Begin()
	b.MarkExhausted("timeout")

	if !b.IsExhausted() {
		t.Error("IsExhausted = false after MarkExhausted")
	}
	if got := b.Reason(); got != "timeout" {
		t.Errorf("Reason = %q, want timeout", got)
	}
	_, _, err := b.AcquireCallDeadline(context.Background())
	if !errors.Is(err, ErrSourceBudgetExhausted) {
		t.Errorf("post-MarkExhausted acquire = %v, want ErrSourceBudgetExhausted", err)
	}
}

func TestSourceBudget_ZeroTotalDurationIsUnlimited(t *testing.T) {
	b := NewSourceBudget("test", 0, 25*time.Millisecond)
	b.Begin()
	time.Sleep(50 * time.Millisecond) // would exhaust if TotalDuration enforced

	ctx, cancel, err := b.AcquireCallDeadline(context.Background())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Error("ctx has no deadline — PerCallTimeout should still apply")
	}
}
