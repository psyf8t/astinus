//go:build !race

package pathclassifier

// raceDetectorEnabled is false in builds without `-race`. The perf
// test in classifier_test.go asserts the 10 µs/path target only when
// the race detector is off — under race, map operations get
// instrumented and the budget would be ~10× tighter than what the
// production hot path actually runs at.
const raceDetectorEnabled = false
