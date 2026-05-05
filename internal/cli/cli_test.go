package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/version"
)

func TestVersionCommandPrintsBanner(t *testing.T) {
	opts := &rootOptions{}
	root := newRootCommand(opts)

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("execute version: %v", err)
	}

	got := strings.TrimSpace(out.String())
	want := version.String()
	if got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

func TestRootRejectsInvalidLogLevel(t *testing.T) {
	opts := &rootOptions{}
	root := newRootCommand(opts)

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--log-level", "verbose", "version"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for invalid --log-level")
	}
	var exitErr *exitError
	if !asExitError(err, &exitErr) {
		t.Fatalf("expected *exitError, got %T: %v", err, err)
	}
	if exitErr.code != ExitInvalidArgs {
		t.Fatalf("exit code = %d, want %d", exitErr.code, ExitInvalidArgs)
	}
}

func TestRootRejectsInvalidLogFormat(t *testing.T) {
	opts := &rootOptions{}
	root := newRootCommand(opts)

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--log-format", "yaml", "version"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for invalid --log-format")
	}
	var exitErr *exitError
	if !asExitError(err, &exitErr) {
		t.Fatalf("expected *exitError, got %T", err)
	}
	if exitErr.code != ExitInvalidArgs {
		t.Fatalf("exit code = %d, want %d", exitErr.code, ExitInvalidArgs)
	}
}

func TestCompletionRejectsUnknownShell(t *testing.T) {
	opts := &rootOptions{}
	root := newRootCommand(opts)

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"completion", "tcsh"})

	if err := root.Execute(); err == nil {
		t.Fatal("expected error for unknown shell")
	}
}

func TestCompletionGeneratesBash(t *testing.T) {
	opts := &rootOptions{}
	root := newRootCommand(opts)

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"completion", "bash"})

	if err := root.Execute(); err != nil {
		t.Fatalf("execute completion bash: %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("bash completion output is empty")
	}
}
