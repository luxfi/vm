// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package server

import (
	"github.com/luxfi/metric"
)

type serverMetrics struct {
	requests metric.CounterVec
	duration metric.HistogramVec
	inflight metric.Gauge
}

func newMetrics(registerer metric.Registerer) (*serverMetrics, error) {
	m := &serverMetrics{
		requests: registerer.NewCounterVec("api_requests_total", "Total number of API requests", []string{"method", "endpoint"}),
		duration: registerer.NewHistogramVec("api_request_duration_seconds", "API request duration in seconds", []string{"method", "endpoint"}, nil),
		inflight: registerer.NewGauge("api_requests_inflight", "Number of inflight API requests"),
	}

	if err := registerer.Register(metric.AsCollector(m.requests)); err != nil {
		return nil, err
	}
	if err := registerer.Register(metric.AsCollector(m.duration)); err != nil {
		return nil, err
	}
	if err := registerer.Register(metric.AsCollector(m.inflight)); err != nil {
		return nil, err
	}

	return m, nil
}
