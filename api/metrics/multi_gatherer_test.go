// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metrics

import (
	"testing"

	"github.com/luxfi/metric"
	"github.com/stretchr/testify/require"
)

var (
	hello      = "hello"
	world      = "world"
	helloWorld = "hello_world"
)

func TestMultiGathererEmptyGather(t *testing.T) {
	require := require.New(t)

	g := NewMultiGatherer()

	mfs, err := g.Gather()
	require.NoError(err)
	require.Empty(mfs)
}

func TestMultiGathererDuplicatedPrefix(t *testing.T) {
	require := require.New(t)

	g := NewMultiGatherer()
	og := NewOptionalGatherer()

	require.NoError(g.Register("foo", og))

	// When using NewMultiGatherer (which returns a PrefixGatherer),
	// duplicate registrations with the same prefix should fail with errOverlappingNamespaces
	err := g.Register("foo", og)
	require.ErrorIs(err, errOverlappingNamespaces)

	// Registering with a different prefix should work
	require.NoError(g.Register("bar", og))
}

func TestMultiGathererAddedError(t *testing.T) {
	require := require.New(t)

	g := NewMultiGatherer()

	tg := &testGatherer{
		err: errTest,
	}

	require.NoError(g.Register("", tg))

	mfs, err := g.Gather()
	require.ErrorIs(err, errTest)
	require.Empty(mfs)
}

func TestMultiGathererNoAddedPrefix(t *testing.T) {
	require := require.New(t)

	g := NewMultiGatherer()

	tg := &testGatherer{
		mfs: []*metric.MetricFamily{{
			Name: hello,
			Type: metric.MetricTypeCounter,
			Metrics: []metric.Metric{
				{Value: metric.MetricValue{Value: 0}},
			},
		}},
	}

	require.NoError(g.Register("", tg))

	mfs, err := g.Gather()
	require.NoError(err)
	require.Len(mfs, 1)
	require.Equal(hello, mfs[0].Name)
}

func TestMultiGathererAddedPrefix(t *testing.T) {
	require := require.New(t)

	g := NewMultiGatherer()

	tg := &testGatherer{
		mfs: []*metric.MetricFamily{{
			Name: world,
			Type: metric.MetricTypeCounter,
			Metrics: []metric.Metric{
				{Value: metric.MetricValue{Value: 0}},
			},
		}},
	}

	require.NoError(g.Register(hello, tg))

	mfs, err := g.Gather()
	require.NoError(err)
	require.Len(mfs, 1)
	// The prefix gatherer combines "hello" + "_" + "world" = "hello_world"
	require.Equal(helloWorld, mfs[0].Name)
}

func TestMultiGathererJustPrefix(t *testing.T) {
	require := require.New(t)

	g := NewMultiGatherer()

	emptyName := ""
	tg := &testGatherer{
		mfs: []*metric.MetricFamily{{
			Name: emptyName,
			Type: metric.MetricTypeCounter,
			Metrics: []metric.Metric{
				{Value: metric.MetricValue{Value: 0}},
			},
		}},
	}

	require.NoError(g.Register(hello, tg))

	mfs, err := g.Gather()
	require.NoError(err)
	require.Len(mfs, 1)
	require.Equal(hello, mfs[0].Name)
}

func TestMultiGathererSorted(t *testing.T) {
	require := require.New(t)

	g := NewMultiGatherer()

	name0 := "a"
	name1 := "z"
	// Create metrics with proper structure
	tg := &testGatherer{
		mfs: []*metric.MetricFamily{
			{
				Name: name1,
				Type: metric.MetricTypeCounter,
				Metrics: []metric.Metric{
					{Value: metric.MetricValue{Value: 0}},
				},
			},
			{
				Name: name0,
				Type: metric.MetricTypeCounter,
				Metrics: []metric.Metric{
					{Value: metric.MetricValue{Value: 0}},
				},
			},
		},
	}

	require.NoError(g.Register("", tg))

	mfs, err := g.Gather()
	require.NoError(err)
	require.Len(mfs, 2)
	// Check that metrics are sorted by name
	require.Equal(name0, mfs[0].Name)
	require.Equal(name1, mfs[1].Name)
}
