// Package runtime detects which build tool produced an OCI image and
// normalises layer history into a representation that hides the
// per-runtime quirks downstream code does not want to think about.
//
// # Why this exists
//
// Astinus's enrichers (layer attribution, base diff, untracked walker)
// were designed against Docker-built images. Real production pipelines
// also use BuildKit, Podman, Buildah, Kaniko, Jib, and Ko — each emits
// OCI-compliant artefacts that differ in subtle but load-bearing ways:
// Kaniko squashes; Podman/Buildah prepend "containers-storage:" to
// CreatedBy strings; BuildKit may attach SLSA provenance attestations
// in a sibling manifest; Jib lays down a fixed three-layer order.
// Without knowing which runtime produced the image, downstream code
// silently degrades on these inputs.
//
// Detect classifies the runtime and returns the evidence that drove
// the decision. Normalize converts the runtime's view of layer history
// into NormalizedLayer entries with the per-runtime prefixes stripped
// and the instruction kind extracted, aligning history entries with
// real (non-empty) tar layers.
//
// The package is read-only with respect to the v1.Image — it does not
// pull blobs or trigger network I/O beyond what its caller has already
// done.
package runtime
