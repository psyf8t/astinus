package pathclassifier

import "time"

// timeNowNs is a tiny indirection so the perf test in classifier_test.go
// can borrow a stable clock without pulling time into the package's
// production code surface.
func timeNowNs() int64 { return time.Now().UnixNano() }
