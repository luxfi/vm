// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metrics

import "github.com/luxfi/metric"

var counterOpts = metric.CounterOpts{
	Name: "counter",
	Help: "help",
}

type testGatherer struct {
	mfs []*metric.MetricFamily
	err error
}

func (g *testGatherer) Gather() ([]*metric.MetricFamily, error) {
	return g.mfs, g.err
}
