// Package runtimes runs the 5-row builder matrix for PRSD-Task-9
// (Docker / BuildKit / Podman / Buildah / Kaniko). Each row builds
// `helpers.SimpleDockerfile` with a different runtime and asserts
// that Astinus's runtime-detection + dedup + NTIA-floor invariants
// hold across builders.
//
// Built only under `//go:build acceptance`.
package runtimes
