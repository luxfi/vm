// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metrics

import (
	"testing"

	"github.com/luxfi/metric"
	"github.com/stretchr/testify/require"
)

func TestLabelGatherer_Gather(t *testing.T) {
	const (
		labelName         = "smith"
		labelValueA       = "rick"
		labelValueB       = "morty"
		customLabelName   = "tag"
		customLabelValueA = "a"
		customLabelValueB = "b"
	)
	tests := []struct {
		name            string
		labelName       string
		expectedMetrics []metric.Metric
		expectErr       bool
	}{
		{
			name:      "no overlap",
			labelName: customLabelName,
			expectedMetrics: []metric.Metric{
				{
					Labels: []metric.LabelPair{
						{Name: labelName, Value: labelValueB},
						{Name: customLabelName, Value: customLabelValueB},
					},
					Value: metric.MetricValue{Value: 1},
				},
				{
					Labels: []metric.LabelPair{
						{Name: labelName, Value: labelValueA},
						{Name: customLabelName, Value: customLabelValueA},
					},
					Value: metric.MetricValue{Value: 0},
				},
			},
			expectErr: false,
		},
		{
			name:      "has overlap",
			labelName: labelName,
			expectedMetrics: []metric.Metric{
				{
					Labels: []metric.LabelPair{
						{Name: labelName, Value: labelValueB},
						{Name: customLabelName, Value: customLabelValueB},
					},
					Value: metric.MetricValue{Value: 1},
				},
			},
			expectErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			gatherer := NewLabelGatherer(labelName)
			require.NotNil(gatherer)

			registerA := metric.NewRegistry()
			require.NoError(gatherer.Register(labelValueA, registerA))
			{
				counterA := metric.NewCounterVec(
					counterOpts,
					[]string{test.labelName},
				)
				counterA.With(metric.Labels{test.labelName: customLabelValueA})
				collector := metric.AsCollector(counterA)
				require.NotNil(collector)
				require.NoError(registerA.Register(collector))
			}

			registerB := metric.NewRegistry()
			require.NoError(gatherer.Register(labelValueB, registerB))
			{
				counterB := metric.NewCounterVec(
					counterOpts,
					[]string{customLabelName},
				)
				counterB.With(metric.Labels{customLabelName: customLabelValueB}).Inc()
				collector := metric.AsCollector(counterB)
				require.NotNil(collector)
				require.NoError(registerB.Register(collector))
			}

			metrics, err := gatherer.Gather()
			if test.expectErr {
				require.Error(err) //nolint:forbidigo // the error is not exported
			} else {
				require.NoError(err)
			}

			require.Equal(
				[]*metric.MetricFamily{
					{
						Name:    counterOpts.Name,
						Help:    counterOpts.Help,
						Type:    metric.MetricTypeCounter,
						Metrics: test.expectedMetrics,
					},
				},
				metrics,
			)
		})
	}
}

func TestLabelGatherer_Registration(t *testing.T) {
	const (
		firstName  = "first"
		secondName = "second"
	)
	firstLabeledGatherer := &labeledGatherer{
		labelValue: firstName,
		gatherer:   &testGatherer{},
	}
	firstLabelGatherer := func() *labelGatherer {
		return &labelGatherer{
			multiGatherer: multiGatherer{
				names: []string{firstLabeledGatherer.labelValue},
				gatherers: []metric.Gatherer{
					firstLabeledGatherer,
				},
			},
		}
	}
	secondLabeledGatherer := &labeledGatherer{
		labelValue: secondName,
		gatherer: &testGatherer{
			mfs: []*metric.MetricFamily{{}},
		},
	}
	secondLabelGatherer := func() *labelGatherer {
		return &labelGatherer{
			multiGatherer: multiGatherer{
				names: []string{
					firstLabeledGatherer.labelValue,
					secondLabeledGatherer.labelValue,
				},
				gatherers: metric.Gatherers{
					firstLabeledGatherer,
					secondLabeledGatherer,
				},
			},
		}
	}
	onlySecondLabeledGatherer := &labelGatherer{
		multiGatherer: multiGatherer{
			names: []string{
				secondLabeledGatherer.labelValue,
			},
			gatherers: metric.Gatherers{
				secondLabeledGatherer,
			},
		},
	}

	registerTests := []struct {
		name                  string
		labelGatherer         *labelGatherer
		labelValue            string
		gatherer              metric.Gatherer
		expectedErr           error
		expectedLabelGatherer *labelGatherer
	}{
		{
			name:                  "first registration",
			labelGatherer:         &labelGatherer{},
			labelValue:            firstName,
			gatherer:              firstLabeledGatherer.gatherer,
			expectedErr:           nil,
			expectedLabelGatherer: firstLabelGatherer(),
		},
		{
			name:                  "second registration",
			labelGatherer:         firstLabelGatherer(),
			labelValue:            secondName,
			gatherer:              secondLabeledGatherer.gatherer,
			expectedErr:           nil,
			expectedLabelGatherer: secondLabelGatherer(),
		},
		{
			name:                  "conflicts with previous registration",
			labelGatherer:         firstLabelGatherer(),
			labelValue:            firstName,
			gatherer:              secondLabeledGatherer.gatherer,
			expectedErr:           errDuplicateGatherer,
			expectedLabelGatherer: firstLabelGatherer(),
		},
	}
	for _, test := range registerTests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			err := test.labelGatherer.Register(test.labelValue, test.gatherer)
			require.ErrorIs(err, test.expectedErr)
			require.Equal(test.expectedLabelGatherer, test.labelGatherer)
		})
	}

	deregisterTests := []struct {
		name                  string
		labelGatherer         *labelGatherer
		labelValue            string
		expectedRemoved       bool
		expectedLabelGatherer *labelGatherer
	}{
		{
			name:                  "remove from nothing",
			labelGatherer:         &labelGatherer{},
			labelValue:            firstName,
			expectedRemoved:       false,
			expectedLabelGatherer: &labelGatherer{},
		},
		{
			name:                  "remove unknown name",
			labelGatherer:         firstLabelGatherer(),
			labelValue:            secondName,
			expectedRemoved:       false,
			expectedLabelGatherer: firstLabelGatherer(),
		},
		{
			name:            "remove first name",
			labelGatherer:   firstLabelGatherer(),
			labelValue:      firstName,
			expectedRemoved: true,
			expectedLabelGatherer: &labelGatherer{
				multiGatherer: multiGatherer{
					// We must populate with empty slices rather than nil slices
					// to pass the equality check.
					names:     []string{},
					gatherers: metric.Gatherers{},
				},
			},
		},
		{
			name:                  "remove second name",
			labelGatherer:         secondLabelGatherer(),
			labelValue:            secondName,
			expectedRemoved:       true,
			expectedLabelGatherer: firstLabelGatherer(),
		},
		{
			name:                  "remove only first name",
			labelGatherer:         secondLabelGatherer(),
			labelValue:            firstName,
			expectedRemoved:       true,
			expectedLabelGatherer: onlySecondLabeledGatherer,
		},
	}
	for _, test := range deregisterTests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			removed := test.labelGatherer.Deregister(test.labelValue)
			require.Equal(test.expectedRemoved, removed)
			require.Equal(test.expectedLabelGatherer, test.labelGatherer)
		})
	}
}
