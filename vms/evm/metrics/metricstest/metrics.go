// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metricstest

import (
	"sync"
	"testing"
)

var metricsLock sync.Mutex

// WithMetrics enables metrics for the test and prevents any other
// tests with metrics from running concurrently.
//
// Metrics are restored to their original value during testing cleanup.
func WithMetrics(t testing.TB) {
	metricsLock.Lock()
	// TODO: Add metric enable/disable support when available
	t.Cleanup(func() {
		metricsLock.Unlock()
	})
}
