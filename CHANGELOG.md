# Changelog

All notable post-stage fixes that change observable behaviour. Stage
deliverables themselves are tracked in the implementation log; this
file is for cross-stage fixes that an operator might bisect against.

## Unreleased

### Security

- Bumped Go toolchain floor from 1.25.0 to 1.25.9. The previous floor
  exposed 19 known stdlib CVEs reported by `govulncheck` (notably
  `GO-2025-4007/4008/4009` reachable via the registry-pull TLS
  handshake). Builders that have only an older local toolchain will
  auto-download 1.25.9 via `GOTOOLCHAIN=auto`. Dockerfile builder
  pinned to `golang:1.25.9-alpine` for reproducibility. The Makefile
  now exports `GOTOOLCHAIN` from the `go` directive so all `go`
  invocations agree on a version. (post-stage-13 review F-001)

### Fixed

- Auto-detection now correctly resolves locally-built images via the
  Docker / Podman daemon before attempting a registry pull. Previously
  failed with `401 UNAUTHORIZED` when the image existed only in the
  local daemon. Probe is gated by a 2-second timeout and a cheap
  socket-existence check, so the new behaviour adds at most a few
  microseconds when no daemon is running. (ADR-0017)
- Format detection now survives truncation of the 64 KiB peek window:
  large minified CycloneDX SBOMs (Syft 1.34+, ~MiB-scale single-line
  JSON) are classified correctly instead of returning
  `unrecognised format`. (ADR-0016)
