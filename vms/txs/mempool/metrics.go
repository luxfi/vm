// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mempool

import (
	"github.com/luxfi/metric"
)

type mempoolMetrics struct {
	numTxs    metric.Gauge
	bytesUsed metric.Gauge
}

func newMetrics(registerer metric.Registerer) (*mempoolMetrics, error) {
	m := &mempoolMetrics{
		numTxs: metric.NewGauge(metric.GaugeOpts{
			Name: "mempool_num_txs",
			Help: "Number of transactions in mempool",
		}),
		bytesUsed: metric.NewGauge(metric.GaugeOpts{
			Name: "mempool_bytes_used",
			Help: "Number of bytes used by mempool",
		}),
	}

	err := registerer.Register(metric.AsCollector(m.numTxs))
	if err != nil {
		return nil, err
	}
	err = registerer.Register(metric.AsCollector(m.bytesUsed))
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (m *mempoolMetrics) Update(numTxs, bytesAvailable int) {
	m.numTxs.Set(float64(numTxs))
	m.bytesUsed.Set(float64(maxMempoolSize - bytesAvailable))
}

// NewMetrics creates a new Metrics instance
func NewMetrics(namespace string, registerer metric.Registerer) (Metrics, error) {
	return newMetrics(registerer)
}
