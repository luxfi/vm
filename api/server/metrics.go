// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package server

import (
	"net/http"

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

func (m *serverMetrics) wrapHandler(chainName string, handler http.Handler) http.Handler {
	// Instrument handler with metrics
	// Note: We wrap with basic instrumentation. For more advanced currying,
	// access the underlying metric types directly.
	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.requests.WithLabelValues(r.Method, chainName).Inc()
		m.inflight.Inc()
		defer m.inflight.Dec()

		timer := m.duration.WithLabelValues(r.Method, chainName)
		defer func(start float64) {
			timer.Observe(float64(start))
		}(float64(0)) // TODO: implement proper timing

		handler.ServeHTTP(w, r)
	})
	return handler
}
