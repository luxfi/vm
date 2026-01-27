//go:build grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"github.com/luxfi/metric"
	io_prometheus_client "github.com/prometheus/client_model/go"
)

// nativeToPrometheusMetrics converts luxfi/metric MetricFamily to prometheus
// client_model MetricFamily. Used when sending metrics over gRPC.
func nativeToPrometheusMetrics(families []*metric.MetricFamily) []*io_prometheus_client.MetricFamily {
	if families == nil {
		return nil
	}
	result := make([]*io_prometheus_client.MetricFamily, 0, len(families))
	for _, mf := range families {
		if mf == nil {
			continue
		}
		promMF := &io_prometheus_client.MetricFamily{
			Name: ptrStr(mf.Name),
			Help: ptrStr(mf.Help),
			Type: nativeTypeToProm(mf.Type).Enum(),
		}
		for _, m := range mf.Metrics {
			promM := nativeMetricToProm(m, mf.Type)
			promMF.Metric = append(promMF.Metric, promM)
		}
		result = append(result, promMF)
	}
	return result
}

func nativeTypeToProm(t metric.MetricType) io_prometheus_client.MetricType {
	switch t {
	case metric.MetricTypeCounter:
		return io_prometheus_client.MetricType_COUNTER
	case metric.MetricTypeGauge:
		return io_prometheus_client.MetricType_GAUGE
	case metric.MetricTypeHistogram:
		return io_prometheus_client.MetricType_HISTOGRAM
	case metric.MetricTypeSummary:
		return io_prometheus_client.MetricType_SUMMARY
	default:
		return io_prometheus_client.MetricType_UNTYPED
	}
}

func nativeLabelsToProm(labels []metric.LabelPair) []*io_prometheus_client.LabelPair {
	if labels == nil {
		return nil
	}
	result := make([]*io_prometheus_client.LabelPair, 0, len(labels))
	for _, lp := range labels {
		result = append(result, &io_prometheus_client.LabelPair{
			Name:  ptrStr(lp.Name),
			Value: ptrStr(lp.Value),
		})
	}
	return result
}

func nativeMetricToProm(m metric.Metric, t metric.MetricType) *io_prometheus_client.Metric {
	promM := &io_prometheus_client.Metric{
		Label: nativeLabelsToProm(m.Labels),
	}
	switch t {
	case metric.MetricTypeCounter:
		promM.Counter = &io_prometheus_client.Counter{
			Value: ptrFloat(m.Value.Value),
		}
	case metric.MetricTypeGauge:
		promM.Gauge = &io_prometheus_client.Gauge{
			Value: ptrFloat(m.Value.Value),
		}
	case metric.MetricTypeHistogram:
		h := &io_prometheus_client.Histogram{
			SampleCount: ptrUint64(m.Value.SampleCount),
			SampleSum:   ptrFloat(m.Value.SampleSum),
		}
		for _, b := range m.Value.Buckets {
			h.Bucket = append(h.Bucket, &io_prometheus_client.Bucket{
				UpperBound:      ptrFloat(b.UpperBound),
				CumulativeCount: ptrUint64(b.CumulativeCount),
			})
		}
		promM.Histogram = h
	case metric.MetricTypeSummary:
		s := &io_prometheus_client.Summary{
			SampleCount: ptrUint64(m.Value.SampleCount),
			SampleSum:   ptrFloat(m.Value.SampleSum),
		}
		for _, q := range m.Value.Quantiles {
			s.Quantile = append(s.Quantile, &io_prometheus_client.Quantile{
				Quantile: ptrFloat(q.Quantile),
				Value:    ptrFloat(q.Value),
			})
		}
		promM.Summary = s
	default:
		promM.Gauge = &io_prometheus_client.Gauge{
			Value: ptrFloat(m.Value.Value),
		}
	}
	return promM
}

func ptrStr(s string) *string {
	return &s
}

func ptrFloat(f float64) *float64 {
	return &f
}

func ptrUint64(u uint64) *uint64 {
	return &u
}

// prometheusToNativeMetrics converts prometheus client_model MetricFamily to
// luxfi/metric MetricFamily. This is needed because the vmpb protobuf uses
// prometheus client_model types directly, but our metric package uses its own types.
func prometheusToNativeMetrics(promFamilies []*io_prometheus_client.MetricFamily) []*metric.MetricFamily {
	if promFamilies == nil {
		return nil
	}
	result := make([]*metric.MetricFamily, 0, len(promFamilies))
	for _, promMF := range promFamilies {
		if promMF == nil {
			continue
		}
		mf := &metric.MetricFamily{
			Name: promMF.GetName(),
			Help: promMF.GetHelp(),
			Type: promTypeToNative(promMF.GetType()),
		}
		for _, promM := range promMF.GetMetric() {
			if promM == nil {
				continue
			}
			m := metric.Metric{
				Labels: promLabelsToNative(promM.GetLabel()),
				Value:  promValueToNative(promM, mf.Type),
			}
			mf.Metrics = append(mf.Metrics, m)
		}
		result = append(result, mf)
	}
	return result
}

func promTypeToNative(t io_prometheus_client.MetricType) metric.MetricType {
	switch t {
	case io_prometheus_client.MetricType_COUNTER:
		return metric.MetricTypeCounter
	case io_prometheus_client.MetricType_GAUGE:
		return metric.MetricTypeGauge
	case io_prometheus_client.MetricType_HISTOGRAM:
		return metric.MetricTypeHistogram
	case io_prometheus_client.MetricType_SUMMARY:
		return metric.MetricTypeSummary
	default:
		return metric.MetricTypeUntyped
	}
}

func promLabelsToNative(labels []*io_prometheus_client.LabelPair) []metric.LabelPair {
	if labels == nil {
		return nil
	}
	result := make([]metric.LabelPair, 0, len(labels))
	for _, lp := range labels {
		if lp == nil {
			continue
		}
		result = append(result, metric.LabelPair{
			Name:  lp.GetName(),
			Value: lp.GetValue(),
		})
	}
	return result
}

func promValueToNative(m *io_prometheus_client.Metric, t metric.MetricType) metric.MetricValue {
	var v metric.MetricValue
	switch t {
	case metric.MetricTypeCounter:
		if c := m.GetCounter(); c != nil {
			v.Value = c.GetValue()
		}
	case metric.MetricTypeGauge:
		if g := m.GetGauge(); g != nil {
			v.Value = g.GetValue()
		}
	case metric.MetricTypeHistogram:
		if h := m.GetHistogram(); h != nil {
			v.SampleCount = h.GetSampleCount()
			v.SampleSum = h.GetSampleSum()
			for _, b := range h.GetBucket() {
				if b != nil {
					v.Buckets = append(v.Buckets, metric.Bucket{
						UpperBound:      b.GetUpperBound(),
						CumulativeCount: b.GetCumulativeCount(),
					})
				}
			}
		}
	case metric.MetricTypeSummary:
		if s := m.GetSummary(); s != nil {
			v.SampleCount = s.GetSampleCount()
			v.SampleSum = s.GetSampleSum()
			for _, q := range s.GetQuantile() {
				if q != nil {
					v.Quantiles = append(v.Quantiles, metric.Quantile{
						Quantile: q.GetQuantile(),
						Value:    q.GetValue(),
					})
				}
			}
		}
	default:
		// For untyped, try counter first, then gauge
		if c := m.GetCounter(); c != nil {
			v.Value = c.GetValue()
		} else if g := m.GetGauge(); g != nil {
			v.Value = g.GetValue()
		}
	}
	return v
}
