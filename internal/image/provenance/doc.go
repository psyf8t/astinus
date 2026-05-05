// Package provenance reads SLSA provenance attestations embedded in
// container images by BuildKit (`docker buildx build --attest=...`).
//
// # What BuildKit produces
//
// When `--attest=type=provenance` is passed, BuildKit emits a manifest
// list (OCI Image Index) that pairs the platform image with a sibling
// "attestation manifest" carrying an in-toto SLSA Provenance v0.2 / v1
// statement as its config blob. The attestation manifest is identified
// by the OCI annotation `vnd.docker.reference.type=attestation-manifest`
// and its `vnd.docker.reference.digest` annotation points back at the
// platform image it attests.
//
// # What this package does
//
// Given a v1.ImageIndex, FindAttestation locates the attestation
// manifest for a target platform image. Given the attestation manifest
// (which is itself a v1.Image whose config blob is a JSON in-toto
// statement, not the usual OCI Config), Extract parses the SLSA
// predicate.
//
// # What this package does NOT do
//
// We do not (yet) verify signatures or cosign attestations layered on
// top of the in-toto statement. Verification is a follow-up concern;
// extraction is a prerequisite for it.
//
// # Limitations
//
// Astinus today receives the platform image (a v1.Image), not the
// containing index. Extract on a plain v1.Image returns (nil, nil)
// — the attestation cannot be reached from there. Callers that hold
// the index can use FindAttestation followed by Extract on the
// returned attestation manifest.
package provenance
