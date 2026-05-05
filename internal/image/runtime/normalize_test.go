package runtime

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestParseInstructionType(t *testing.T) {
	cases := map[string]InstructionType{
		"": InstructionUNKNOWN,
		"/bin/sh -c #(nop) COPY file:abc in /app/":          InstructionCOPY,
		"/bin/sh -c #(nop) ADD file:abc in /app/":           InstructionADD,
		"/bin/sh -c #(nop) ENV FOO=bar":                     InstructionENV,
		"/bin/sh -c #(nop) LABEL maintainer=ops":            InstructionLABEL,
		"/bin/sh -c #(nop)  ARG GO_VERSION":                 InstructionARG,
		"/bin/sh -c #(nop) FROM scratch":                    InstructionFROM,
		"RUN /bin/sh -c apt-get update":                     InstructionRUN,
		"COPY file:abc in /app/":                            InstructionCOPY,
		"/bin/sh -c apt-get update && apt-get install curl": InstructionRUN,
		"/bin/bash -c something":                            InstructionRUN,
		"random unrecognised string":                        InstructionUNKNOWN,
	}
	for in, want := range cases {
		if got := parseInstructionType(in); got != want {
			t.Errorf("parseInstructionType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeNilImage(t *testing.T) {
	if _, err := Normalize(RuntimeDocker, nil); err == nil {
		t.Fatal("expected error for nil image")
	}
}

// TestNormalizeAlignsHistoryWithLayers verifies that EmptyLayer
// history entries are skipped during alignment so non-empty entries
// pair up with real tar layers.
func TestNormalizeAlignsHistoryWithLayers(t *testing.T) {
	cf := v1.ConfigFile{
		History: []v1.History{
			{CreatedBy: "FROM scratch", EmptyLayer: false},                        // pairs layer 0
			{CreatedBy: "ENV PATH=/usr/local/bin:$PATH", EmptyLayer: true},        // skipped
			{CreatedBy: "RUN /bin/sh -c apt-get update", EmptyLayer: false},       // pairs layer 1
			{CreatedBy: "LABEL org.opencontainers.image.foo=1", EmptyLayer: true}, // skipped
			{CreatedBy: "COPY app /app", EmptyLayer: false},                       // pairs layer 2
		},
	}
	img := imageWithLayersAndConfig(t, 3, cf)

	got, err := Normalize(RuntimeDocker, img)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3", len(got))
	}
	wantCreatedBy := []string{
		"FROM scratch",
		"RUN /bin/sh -c apt-get update",
		"COPY app /app",
	}
	for i, want := range wantCreatedBy {
		if got[i].CreatedBy != want {
			t.Errorf("layer %d CreatedBy = %q, want %q", i, got[i].CreatedBy, want)
		}
	}
	if got[0].InstructionType != InstructionFROM {
		t.Errorf("layer 0 instruction = %q, want FROM", got[0].InstructionType)
	}
	if got[1].InstructionType != InstructionRUN {
		t.Errorf("layer 1 instruction = %q, want RUN", got[1].InstructionType)
	}
	if got[2].InstructionType != InstructionCOPY {
		t.Errorf("layer 2 instruction = %q, want COPY", got[2].InstructionType)
	}
}

func TestNormalizeKanikoMarksSquashed(t *testing.T) {
	cf := v1.ConfigFile{
		History: []v1.History{
			{CreatedBy: "RUN apt-get update"},
		},
	}
	img := imageWithLayersAndConfig(t, 1, cf)

	got, err := Normalize(RuntimeKaniko, img)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if got[0].RuntimeMetadata["squashed"] != "likely" {
		t.Errorf("RuntimeMetadata[squashed] = %q, want likely", got[0].RuntimeMetadata["squashed"])
	}
}

func TestNormalizePodmanStripsContainersStoragePrefix(t *testing.T) {
	cf := v1.ConfigFile{
		History: []v1.History{
			{CreatedBy: "containers-storage:RUN apt-get update"},
		},
	}
	img := imageWithLayersAndConfig(t, 1, cf)

	got, err := Normalize(RuntimePodman, img)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if got[0].CreatedBy != "RUN apt-get update" {
		t.Errorf("CreatedBy = %q, want stripped 'RUN apt-get update'", got[0].CreatedBy)
	}
	if got[0].InstructionType != InstructionRUN {
		t.Errorf("InstructionType = %q, want RUN (re-parsed after strip)", got[0].InstructionType)
	}
}

func TestNormalizeBuildKitStripsBuildKitPrefix(t *testing.T) {
	cf := v1.ConfigFile{
		History: []v1.History{
			{CreatedBy: "buildkit.dockerfile.v0:COPY app /app"},
		},
	}
	img := imageWithLayersAndConfig(t, 1, cf)

	got, err := Normalize(RuntimeBuildKit, img)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if got[0].CreatedBy != "COPY app /app" {
		t.Errorf("CreatedBy = %q, want 'COPY app /app'", got[0].CreatedBy)
	}
	if got[0].InstructionType != InstructionCOPY {
		t.Errorf("InstructionType = %q, want COPY", got[0].InstructionType)
	}
}

func TestNormalizeMissingHistoryLeavesUnknown(t *testing.T) {
	cf := v1.ConfigFile{} // no history at all
	img := imageWithLayersAndConfig(t, 2, cf)

	got, err := Normalize(RuntimeDocker, img)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	for i, nl := range got {
		if nl.CreatedBy != "" {
			t.Errorf("layer %d CreatedBy = %q, want empty", i, nl.CreatedBy)
		}
		if nl.InstructionType != InstructionUNKNOWN {
			t.Errorf("layer %d InstructionType = %q, want UNKNOWN", i, nl.InstructionType)
		}
	}
}

func TestNormalizePopulatesDigestAndDiffID(t *testing.T) {
	cf := v1.ConfigFile{
		History: []v1.History{{CreatedBy: "FROM scratch"}},
	}
	img := imageWithLayersAndConfig(t, 1, cf)

	got, err := Normalize(RuntimeDocker, img)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if got[0].Digest == "" {
		t.Errorf("Digest is empty")
	}
	if got[0].DiffID == "" {
		t.Errorf("DiffID is empty")
	}
	if got[0].Size <= 0 {
		t.Errorf("Size = %d, want > 0", got[0].Size)
	}
}
