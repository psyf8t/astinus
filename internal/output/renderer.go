// Package output renders an enriched SBOM to whichever wire format
// the CLI was asked for.
//
// Stage 3 ships:
//
//   - cyclonedx-json (default; "same" when input is CycloneDX)
//
// Stage 7 adds SPDX, Stage 11 adds SARIF / human summary. The
// Renderer interface is the extension point — new formats register
// themselves with `RegisterFormat`.
//
// The CLI uses the helpers in stdout.go to hand back an io.Writer
// for either a file path or "-" (stdout) so the rendering side stays
// I/O-agnostic.
package output

import (
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Renderer turns a canonical SBOM into bytes on the wire.
type Renderer interface {
	// Name is the CLI identifier (`--output-format <name>`).
	Name() string

	// MIMEType returns the IANA type for HTTP/file headers.
	// Used by the CLI when --output is "-" and stdout is being piped
	// to a tool that respects the type (rare today; future-proof).
	MIMEType() string

	// Render serialises sbom to w. Implementations MUST stream when
	// possible so a 100 MB SBOM doesn't double in memory.
	Render(w io.Writer, sbom *model.SBOM) error
}

// Options is the per-render knob bag. Today only Pretty is
// honoured; later formats (SARIF, summary) will add format-specific
// fields.
type Options struct {
	// Pretty toggles indented output where the format supports it.
	Pretty bool
}

var (
	registryMu sync.RWMutex
	registry   = map[string]factory{}
)

// factory builds a Renderer with the requested options.
type factory func(Options) Renderer

// RegisterFormat registers a renderer factory under the given name.
// Panics on duplicate registration so the bug surfaces at init() time.
func RegisterFormat(name string, f factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[name]; exists {
		panic("output: duplicate renderer registration: " + name)
	}
	registry[name] = f
}

// Get returns the renderer registered under name. Returns an error
// the CLI can surface verbatim when the user asks for an unknown
// format.
func Get(name string, opts Options) (Renderer, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	f, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("output: unknown format %q (known: %v)", name, knownLocked())
	}
	return f(opts), nil
}

// Known returns the registered format names sorted alphabetically.
func Known() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return knownLocked()
}

// knownLocked returns the sorted format list. Caller must hold
// registryMu.
func knownLocked() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
