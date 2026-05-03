package helpers

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"
)

// TB is the subset of *testing.T / *testing.B every helper needs.
// Helpers take TB so the same code runs from acceptance tests AND
// benchmarks without duplication.
type TB interface {
	Helper()
	Logf(format string, args ...any)
	Fatalf(format string, args ...any)
	Skipf(format string, args ...any)
	TempDir() string
	Cleanup(func())
}

// RequireCommand t.Skip()s when name is not on PATH. Mirrors the
// requireCommand helper from the task spec — every external-tool
// test starts with this so the suite is fail-soft on dev boxes.
func RequireCommand(t TB, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("acceptance: %q not on PATH (%v) — skipping", name, err)
	}
}

// RequireDockerDaemon skips the test when the docker CLI is missing
// or `docker info` cannot reach a running daemon. This is the
// dominant skip path on developer machines.
func RequireDockerDaemon(t TB) {
	t.Helper()
	RequireCommand(t, "docker")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skipf("acceptance: docker daemon unreachable (%v) — skipping", err)
	}
}

// RunOK executes cmd and t.Fatalf on non-zero exit. Returns combined
// stdout+stderr for callers that need the output. The 10-minute
// timeout matches the longest legitimate command in the suite (a
// full image build); shorter callers can pass a context-bound *Cmd
// via RunOKContext.
func RunOK(t TB, name string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return RunOKContext(t, ctx, name, args...)
}

// RunOKContext is the context-aware variant of RunOK.
func RunOKContext(t TB, ctx context.Context, name string, args ...string) []byte {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		t.Fatalf("acceptance: %s %v failed: %v\n----- output -----\n%s\n------------------",
			name, args, err, buf.String())
	}
	return buf.Bytes()
}

// Run is RunOK without the failure path; returns combined output
// AND the underlying error so callers can branch on success / fail
// (used by validators that exit non-zero on schema breaks).
//
// A 60-second context guards against hung commands (lookup tools,
// daemon probes); callers needing a different cap should use
// RunContext.
func Run(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return RunContext(ctx, name, args...)
}

// RunContext is the context-aware variant of Run.
func RunContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

// FormatRunFailure renders a uniform "command X failed with output Y"
// error string. Pulled into a helper so tests don't grow inconsistent
// error formatting across files.
func FormatRunFailure(name string, args []string, err error, output []byte) string {
	return fmt.Sprintf("%s %v failed: %v\noutput:\n%s",
		name, args, err, string(output))
}

// Skip returns true when t was already configured to skip — used by
// the runtime matrix to short-circuit further work.
func Skip(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Skipf(format, args...)
}
