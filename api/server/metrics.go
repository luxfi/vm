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
		requests: metric.NewCounterVec(
			metric.CounterOpts{
				Name: "api_requests_total",
				Help: "Total number of API requests",
			},
			[]string{"method", "endpoint"},
		),
		duration: metric.NewHistogramVec(
			metric.HistogramOpts{
				Name: "api_request_duration_seconds",
				Help: "API request duration in seconds",
			},
			[]string{"method", "endpoint"},
		),
		inflight: metric.NewGauge(
			metric.GaugeOpts{
				Name: "api_requests_inflight",
				Help: "Number of inflight API requests",
			},
		),
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
