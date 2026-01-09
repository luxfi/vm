// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package nets

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/consensus/config"
	"github.com/luxfi/ids"
	"github.com/luxfi/math/set"
)

var validParameters = config.Parameters{
	K:                     1,
	Alpha:                 0.8, // Required for validation
	Beta:                  1,
	AlphaPreference:       1,
	AlphaConfidence:       1,
	BetaVirtuous:          1,
	BetaRogue:             1,
	ConcurrentPolls:       1,
	OptimalProcessing:     1,
	MaxOutstandingItems:   1,
	MaxItemProcessingTime: 1,
}

func TestValid(t *testing.T) {
	tests := []struct {
		name        string
		s           Config
		expectedErr error
	}{
		{
			name: "invalid consensus parameters",
			s: Config{
				ConsensusParameters: config.Parameters{
					K:               2,
					AlphaPreference: 1,
				},
			},
			expectedErr: config.ErrParametersInvalid,
		},
		{
			name: "invalid allowed node IDs",
			s: Config{
				AllowedNodes:        set.Of(ids.GenerateTestNodeID()),
				ValidatorOnly:       false,
				ConsensusParameters: validParameters,
			},
			expectedErr: errAllowedNodesWhenNotValidatorOnly,
		},
		{
			name: "valid",
			s: Config{
				ConsensusParameters: validParameters,
				ValidatorOnly:       false,
			},
			expectedErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.s.Valid()
			require.ErrorIs(t, err, tt.expectedErr)
		})
	}
}
