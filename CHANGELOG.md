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

- SBOM input is now capped at 256 MiB across every reader (format
  detector, CycloneDX, SPDX JSON / tag-value, CLI stdin and file
  paths). Previously every loader called `io.ReadAll` with no upper
  bound; a runaway scan or hostile input could OOM the process
  before parsing started. Inputs above the cap are rejected with
  `ErrSBOMTooLarge`. (post-stage-13 review F-005)
- The `enrich` output writer's `Close()` error is now checked. A
  flush failure on output (disk full, broken pipe, FS quota) used
  to silently produce a truncated SBOM with exit code 0; it now
  surfaces as `ExitOutputWrite`. (post-stage-13 review F-003)
- SBOM format detection now strips a leading UTF-8 BOM
  (`0xEF 0xBB 0xBF`) before the shape check. Previously, SBOMs saved
  by Windows tooling (Notepad, PowerShell, some Excel exports)
  returned `unrecognised format` because the BOM is not Unicode
  whitespace. UTF-16 inputs (`0xFF 0xFE` / `0xFE 0xFF`) now produce
  a clear `ErrUTF16NotSupported` error instead of silent
  `FormatUnknown`. (post-stage-13 review F-002)
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
