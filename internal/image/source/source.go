// Package source loads container images from registries, tar archives,
// OCI layouts, and (eventually) container daemons.
//
// The package exposes one interface (ImageSource) and one factory
// (Factory). Stage 2 ships registry and archive sources; OCI layout
// and daemon sources land in Stage 8.
//
// # Reference schemes
//
// The factory recognises the following reference forms:
//
//	registry-host/path:tag           // default if no scheme
//	registry-host/path@sha256:...    // by digest
//	docker-daemon://name:tag         // Stage 8
//	podman-daemon://name:tag         // Stage 8
//	archive://path/to.tar            // explicit archive
//	oci://path/to/layout             // explicit OCI layout (Stage 8)
//
// Auto-detection rules (when no scheme is given):
//
//  1. If the string parses as a valid registry reference, use the
//     registry source.
//  2. If the string is an existing file and looks like a tar archive,
//     use the archive source.
//  3. If the string is an existing directory containing index.json,
//     use the OCI layout source (Stage 8).
package source

import (
	"context"
	"errors"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// ImageSource is one container image loaded from somewhere.
//
// Implementations are responsible for managing whatever resources the
// underlying source needs (open file handles, HTTP transports, etc.)
// and releasing them when Close is called.
type ImageSource interface {
	// Reference returns the canonical reference for this image. For
	// registry sources this is the parsed `name.Reference`; for
	// archive sources it's the tag the archive was loaded with (or
	// a synthetic "archive:<basename>" reference if untagged).
	Reference() name.Reference

	// Image returns the v1.Image. Multiple calls MAY return the same
	// underlying object — callers should not assume independent
	// state.
	Image(ctx context.Context) (v1.Image, error)

	// Close releases resources. Calling Close more than once is a
	// no-op; calling Image after Close is undefined.
	Close() error
}

// ErrNotFound is returned by sources when the requested image cannot
// be located (registry 404, missing file, missing tag in archive).
var ErrNotFound = errors.New("source: image not found")

// ErrUnsupportedScheme is returned by Factory.FromReference when the
// reference uses a scheme that is recognised but not implemented in
// this stage (e.g. docker-daemon:// before Stage 8).
var ErrUnsupportedScheme = errors.New("source: unsupported scheme")
