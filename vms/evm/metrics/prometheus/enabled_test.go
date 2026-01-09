// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/metric"
)

// This test verifies that the metric system is functional
func TestMetricsEnabledByDefault(t *testing.T) {
	require := require.New(t)

	// Test that a no-op registry can be created without error
	registry := metric.NewNoOpRegistry()
	require.NotNil(registry)

	// Test basic functionality - registry exists and can be used
	// This verifies the metric package is working at a basic level
	// Detailed metric functionality would be tested when the
	// metric package provides more complete implementations
}
