// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metrics

import (
	"testing"

	"github.com/luxfi/metric"
	"github.com/stretchr/testify/require"
)

func TestPrefixGatherer_Gather(t *testing.T) {
	require := require.New(t)

	gatherer := NewPrefixGatherer()
	require.NotNil(gatherer)

	registerA := metric.NewRegistry()
	require.NoError(gatherer.Register("a", registerA))
	{
		counterA := metric.NewCounter(counterOpts)
		collector := metric.AsCollector(counterA)
		require.NotNil(collector)
		require.NoError(registerA.Register(collector))
	}

	registerB := metric.NewRegistry()
	require.NoError(gatherer.Register("b", registerB))
	{
		counterB := metric.NewCounter(counterOpts)
		counterB.Inc()
		collector := metric.AsCollector(counterB)
		require.NotNil(collector)
		require.NoError(registerB.Register(collector))
	}

	metrics, err := gatherer.Gather()
	require.NoError(err)

	require.Equal(
		[]*metric.MetricFamily{
			{
				Name: "a_counter",
				Help: counterOpts.Help,
				Type: metric.MetricTypeCounter,
				Metrics: []metric.Metric{
					{Value: metric.MetricValue{Value: 0}},
				},
			},
			{
				Name: "b_counter",
				Help: counterOpts.Help,
				Type: metric.MetricTypeCounter,
				Metrics: []metric.Metric{
					{Value: metric.MetricValue{Value: 1}},
				},
			},
		},
		metrics,
	)
}

func TestPrefixGatherer_Register(t *testing.T) {
	firstPrefix := "first"
	firstPrefixPtr := &firstPrefix
	firstPrefixedGatherer := &prefixedGatherer{
		prefix:    firstPrefix,
		prefixPtr: firstPrefixPtr,
		gatherer:  &testGatherer{},
	}
	firstPrefixGatherer := func() *prefixGatherer {
		return &prefixGatherer{
			multiGatherer: multiGatherer{
				names: []string{
					firstPrefixedGatherer.prefix,
				},
				gatherers: []metric.Gatherer{
					firstPrefixedGatherer,
				},
			},
		}
	}
	secondPrefix := "second"
	secondPrefixPtr := &secondPrefix
	secondPrefixedGatherer := &prefixedGatherer{
		prefix:    secondPrefix,
		prefixPtr: secondPrefixPtr,
		gatherer: &testGatherer{
			mfs: []*metric.MetricFamily{{}},
		},
	}
	secondPrefixGatherer := &prefixGatherer{
		multiGatherer: multiGatherer{
			names: []string{
				firstPrefixedGatherer.prefix,
				secondPrefixedGatherer.prefix,
			},
			gatherers: []metric.Gatherer{
				firstPrefixedGatherer,
				secondPrefixedGatherer,
			},
		},
	}

	tests := []struct {
		name                   string
		prefixGatherer         *prefixGatherer
		prefix                 string
		gatherer               metric.Gatherer
		expectedErr            error
		expectedPrefixGatherer *prefixGatherer
	}{
		{
			name:                   "first registration",
			prefixGatherer:         &prefixGatherer{},
			prefix:                 firstPrefixedGatherer.prefix,
			gatherer:               firstPrefixedGatherer.gatherer,
			expectedErr:            nil,
			expectedPrefixGatherer: firstPrefixGatherer(),
		},
		{
			name:                   "second registration",
			prefixGatherer:         firstPrefixGatherer(),
			prefix:                 secondPrefixedGatherer.prefix,
			gatherer:               secondPrefixedGatherer.gatherer,
			expectedErr:            nil,
			expectedPrefixGatherer: secondPrefixGatherer,
		},
		{
			name:                   "conflicts with previous registration",
			prefixGatherer:         firstPrefixGatherer(),
			prefix:                 firstPrefixedGatherer.prefix,
			gatherer:               secondPrefixedGatherer.gatherer,
			expectedErr:            errOverlappingNamespaces,
			expectedPrefixGatherer: firstPrefixGatherer(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			err := test.prefixGatherer.Register(test.prefix, test.gatherer)
			require.ErrorIs(err, test.expectedErr)
			require.Equal(test.expectedPrefixGatherer, test.prefixGatherer)
		})
	}
}

func TestEitherIsPrefix(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected bool
	}{
		{
			name:     "empty strings",
			a:        "",
			b:        "",
			expected: true,
		},
		{
			name:     "an empty string",
			a:        "",
			b:        "hello",
			expected: true,
		},
		{
			name:     "same strings",
			a:        "x",
			b:        "x",
			expected: true,
		},
		{
			name:     "different strings",
			a:        "x",
			b:        "y",
			expected: false,
		},
		{
			name:     "splits namespace",
			a:        "hello",
			b:        "hello_world",
			expected: true,
		},
		{
			name:     "is prefix before separator",
			a:        "hello",
			b:        "helloworld",
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			require.Equal(test.expected, eitherIsPrefix(test.a, test.b))
			require.Equal(test.expected, eitherIsPrefix(test.b, test.a))
		})
	}
}
