package telemetry_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoStdlibLogInProductionCode enforces the PRSD-Task-8 contract
// that all log emission flows through `log/slog`. The stdlib
// `"log"` package writes to a global logger and bypasses our
// configured handler, so a single accidental import of it would
// silently degrade the structured-logging discipline this task
// installed.
//
// The test scans every non-test .go file under internal/ and cmd/
// for an import of `"log"`. Tests are exempt because the standard
// `testing.T.Logf` style is fine; production code is not.
func TestNoStdlibLogInProductionCode(t *testing.T) {
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("abs repo root: %v", err)
	}
	roots := []string{
		filepath.Join(repoRoot, "internal"),
		filepath.Join(repoRoot, "cmd"),
	}

	var offenders []string
	fset := token.NewFileSet()
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imp := range f.Imports {
				if imp.Path.Value == `"log"` {
					rel, _ := filepath.Rel(repoRoot, path)
					offenders = append(offenders, rel)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(offenders) > 0 {
		t.Errorf("stdlib `log` package imported in production code (use log/slog via internal/telemetry):\n  %s",
			strings.Join(offenders, "\n  "))
	}
}
