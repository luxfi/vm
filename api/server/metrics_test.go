// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package server

import (
	"testing"

	"github.com/luxfi/metric"
	"github.com/stretchr/testify/require"
)

func TestNewMetrics(t *testing.T) {
	// Create a new registry for testing
	reg := metric.NewRegistry()

	// Create metrics
	metrics, err := newMetrics(reg)
	require.NoError(t, err)
	require.NotNil(t, metrics)
	require.NotNil(t, metrics.requests)
	require.NotNil(t, metrics.duration)
	require.NotNil(t, metrics.inflight)

	// Test basic operations to ensure they work
	metrics.requests.WithLabelValues("GET", "/test").Inc()
	metrics.duration.WithLabelValues("POST", "/api").Observe(0.5)
	metrics.inflight.Inc()
	metrics.inflight.Dec()
}

// TestMetricsMultipleRegistrations verifies that metrics can be created
// on separate registries without conflict.
func TestMetricsMultipleRegistrations(t *testing.T) {
	reg1 := metric.NewRegistry()
	reg2 := metric.NewRegistry()

	// First registration should succeed
	metrics1, err := newMetrics(reg1)
	require.NoError(t, err)
	require.NotNil(t, metrics1)

	// Second registration on different registry should also succeed
	metrics2, err := newMetrics(reg2)
	require.NoError(t, err)
	require.NotNil(t, metrics2)

	// Both should be usable
	metrics1.requests.WithLabelValues("GET", "/test").Inc()
	metrics2.requests.WithLabelValues("POST", "/test").Inc()
}

func TestMetricsOperations(t *testing.T) {
	reg := metric.NewRegistry()

	metrics, err := newMetrics(reg)
	require.NoError(t, err)

	// Test various label combinations
	testCases := []struct {
		method   string
		endpoint string
		duration float64
	}{
		{"GET", "/health", 0.001},
		{"POST", "/api/v1/users", 0.123},
		{"PUT", "/api/v1/users/123", 0.456},
		{"DELETE", "/api/v1/users/456", 0.789},
		{"GET", "/metrics", 0.002},
	}

	for _, tc := range testCases {
		// Increment request counter
		metrics.requests.WithLabelValues(tc.method, tc.endpoint).Inc()

		// Observe duration
		metrics.duration.WithLabelValues(tc.method, tc.endpoint).Observe(tc.duration)

		// Simulate inflight request
		metrics.inflight.Inc()
		metrics.inflight.Dec()
	}

	// Operations completed successfully without panics
}

// TestMetricsRegistrationFailure pins the other half of the question
// TestMetricsMultipleRegistrations asks: two registrations on the SAME registry
// collide, and newMetrics reports it rather than returning a half-built set.
func TestMetricsRegistrationFailure(t *testing.T) {
	reg := metric.NewRegistry()

	metrics1, err := newMetrics(reg)
	require.NoError(t, err)
	require.NotNil(t, metrics1)

	metrics2, err := newMetrics(reg)
	require.Error(t, err, "second registration on the same registry should fail as a duplicate")
	require.Nil(t, metrics2)
}
