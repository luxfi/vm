// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/luxfi/metric"
	. "github.com/luxfi/vm/vms/evm/metrics"
)

var (
	_ metric.Gatherer = (*Gatherer)(nil)

	errMetricSkip             = errors.New("metric skipped")
	errMetricTypeNotSupported = errors.New("metric type is not supported")
	quantiles                 = []float64{.5, .75, .95, .99, .999, .9999}
	pvShortPercent            = []float64{50, 95, 99}
)

// Gatherer implements the [metric.Gatherer] interface by gathering all
// metrics from a [Registry].
type Gatherer struct {
	registry Registry
}

// Gather gathers metrics from the registry and converts them to
// a slice of metric families.
func (g *Gatherer) Gather() ([]*metric.MetricFamily, error) {
	// Gather and pre-sort the metrics to avoid random listings
	var names []string
	g.registry.Each(func(name string, _ any) {
		names = append(names, name)
	})
	slices.Sort(names)

	var (
		mfs  = make([]*metric.MetricFamily, 0, len(names))
		errs []error
	)
	for _, name := range names {
		mf, err := metricFamily(g.registry, name)
		switch {
		case err == nil:
			mfs = append(mfs, mf)
		case !errors.Is(err, errMetricSkip):
			errs = append(errs, err)
		}
	}

	return mfs, errors.Join(errs...)
}

// NewGatherer returns a [Gatherer] using the given registry.
func NewGatherer(registry Registry) *Gatherer {
	return &Gatherer{
		registry: registry,
	}
}

func metricFamily(registry Registry, name string) (mf *metric.MetricFamily, err error) {
	m := registry.Get(name)
	name = strings.ReplaceAll(name, "/", "_")

	switch mt := m.(type) {
	case Counter:
		return &metric.MetricFamily{
			Name: name,
			Type: metric.MetricTypeCounter,
			Metrics: []metric.Metric{{
				Value: metric.MetricValue{
					Value: float64(mt.Snapshot().Count()),
				},
			}},
		}, nil
	case CounterFloat64:
		return &metric.MetricFamily{
			Name: name,
			Type: metric.MetricTypeCounter,
			Metrics: []metric.Metric{{
				Value: metric.MetricValue{
					Value: mt.Snapshot().Count(),
				},
			}},
		}, nil
	case Gauge:
		return &metric.MetricFamily{
			Name: name,
			Type: metric.MetricTypeGauge,
			Metrics: []metric.Metric{{
				Value: metric.MetricValue{
					Value: float64(mt.Snapshot().Value()),
				},
			}},
		}, nil
	case GaugeFloat64:
		return &metric.MetricFamily{
			Name: name,
			Type: metric.MetricTypeGauge,
			Metrics: []metric.Metric{{
				Value: metric.MetricValue{
					Value: mt.Snapshot().Value(),
				},
			}},
		}, nil
	case GaugeInfo:
		return nil, fmt.Errorf("%w: %q is a %T", errMetricSkip, name, m)
	case Histogram:
		snapshot := mt.Snapshot()
		thresholds := snapshot.Percentiles(quantiles)
		nativeQuantiles := make([]metric.Quantile, len(quantiles))
		for i := range thresholds {
			nativeQuantiles[i] = metric.Quantile{
				Quantile: quantiles[i],
				Value:    thresholds[i],
			}
		}
		return &metric.MetricFamily{
			Name: name,
			Type: metric.MetricTypeSummary,
			Metrics: []metric.Metric{{
				Value: metric.MetricValue{
					SampleCount: uint64(snapshot.Count()),
					SampleSum:   float64(snapshot.Sum()),
					Quantiles:   nativeQuantiles,
				},
			}},
		}, nil
	case Meter:
		return &metric.MetricFamily{
			Name: name,
			Type: metric.MetricTypeGauge,
			Metrics: []metric.Metric{{
				Value: metric.MetricValue{
					Value: float64(mt.Snapshot().Count()),
				},
			}},
		}, nil
	case Timer:
		snapshot := mt.Snapshot()
		thresholds := snapshot.Percentiles(quantiles)
		nativeQuantiles := make([]metric.Quantile, len(quantiles))
		for i := range thresholds {
			nativeQuantiles[i] = metric.Quantile{
				Quantile: quantiles[i],
				Value:    thresholds[i],
			}
		}
		return &metric.MetricFamily{
			Name: name,
			Type: metric.MetricTypeSummary,
			Metrics: []metric.Metric{{
				Value: metric.MetricValue{
					SampleCount: uint64(snapshot.Count()),
					SampleSum:   float64(snapshot.Sum()),
					Quantiles:   nativeQuantiles,
				},
			}},
		}, nil
	case ResettingTimer:
		snapshot := mt.Snapshot()
		thresholds := snapshot.Percentiles(pvShortPercent)
		nativeQuantiles := make([]metric.Quantile, len(pvShortPercent))
		for i := range pvShortPercent {
			nativeQuantiles[i] = metric.Quantile{
				Quantile: pvShortPercent[i],
				Value:    thresholds[i],
			}
		}
		count := snapshot.Count()
		return &metric.MetricFamily{
			Name: name,
			Type: metric.MetricTypeSummary,
			Metrics: []metric.Metric{{
				Value: metric.MetricValue{
					SampleCount: uint64(count),
					SampleSum:   float64(count) * snapshot.Mean(),
					Quantiles:   nativeQuantiles,
				},
			}},
		}, nil
	default:
		return nil, fmt.Errorf("%w: metric %q type %T", errMetricTypeNotSupported, name, m)
	}
}
