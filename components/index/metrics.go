// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package index

import "github.com/luxfi/metric"

type indexMetrics struct {
	numObjects    metric.Gauge
	numTxsIndexed metric.Counter
}

func newMetrics(registerer metric.Registerer) (*indexMetrics, error) {
	// Check if registerer implements the Metrics interface
	if metricsImpl, ok := registerer.(interface {
		NewGauge(name, help string) metric.Gauge
		NewCounter(name, help string) metric.Counter
	}); ok {
		m := &indexMetrics{
			numObjects: metricsImpl.NewGauge(
				"index_num_objects",
				"Number of objects in the index",
			),
			numTxsIndexed: metricsImpl.NewCounter(
				"index_txs_indexed",
				"Number of transactions indexed",
			),
		}
		return m, nil
	}

	// If not available, create noop metrics
	return &indexMetrics{
		numObjects:    metric.NewNoopGauge(),
		numTxsIndexed: metric.NewNoopCounter(),
	}, nil
}
