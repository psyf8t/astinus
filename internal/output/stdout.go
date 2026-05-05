package output

import (
	"fmt"
	"io"
	"os"
)

// StdoutPath is the conventional CLI sentinel for "write to standard
// output" (e.g. `--output -`).
const StdoutPath = "-"

// Open returns an io.WriteCloser for path. The special value
// StdoutPath ("-") returns a wrapper around os.Stdout whose Close is
// a no-op (we MUST NOT close stdout — subsequent writes from the CLI
// would silently lose data). Any other path is opened with O_CREATE|
// O_TRUNC|O_WRONLY mode 0o644.
//
// The caller is responsible for calling Close.
func Open(path string) (io.WriteCloser, error) {
	if path == "" {
		return nil, fmt.Errorf("output: empty path")
	}
	if path == StdoutPath {
		return nopCloser{os.Stdout}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("output: open %s: %w", path, err)
	}
	return f, nil
}

// nopCloser wraps an io.Writer so it satisfies io.WriteCloser
// without actually closing the underlying writer (used for stdout).
type nopCloser struct{ w io.Writer }

func (n nopCloser) Write(p []byte) (int, error) { return n.w.Write(p) }
func (n nopCloser) Close() error                { return nil }
