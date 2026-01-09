// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metrics

import (
	"context"

	"github.com/luxfi/metric"
)

type testGathererWithContext struct {
	mfs []*metric.MetricFamily
}

func (g *testGathererWithContext) Gather(context.Context) ([]*metric.MetricFamily, error) {
	return g.mfs, nil
}
