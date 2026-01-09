// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package validators_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	validators "github.com/luxfi/consensus/validator"
	"github.com/luxfi/constants"
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/crypto/bls/signer/localsigner"
	"github.com/luxfi/ids"
	"github.com/luxfi/timer/mockable"
	"github.com/luxfi/upgrade/upgradetest"
	"github.com/luxfi/vm/vms/platformvm/block"
	"github.com/luxfi/vm/vms/platformvm/config"
	"github.com/luxfi/vm/vms/platformvm/genesis/genesistest"
	"github.com/luxfi/vm/vms/platformvm/metrics"
	"github.com/luxfi/vm/vms/platformvm/state"
	"github.com/luxfi/vm/vms/platformvm/state/statetest"

	. "github.com/luxfi/vm/vms/platformvm/validators"
)

func TestGetValidatorSet_AfterEtna(t *testing.T) {
	require := require.New(t)

	vdrs := validators.NewManager()
	upgrades := upgradetest.GetConfig(upgradetest.Durango)
	upgradeTime := genesistest.DefaultValidatorStartTime.Add(2 * time.Second)
	upgrades.EtnaTime = upgradeTime
	s := statetest.New(t, statetest.Config{
		Validators: vdrs,
		Upgrades:   upgrades,
	})

	sk, err := localsigner.New()
	require.NoError(err)
	var (
		chainID       = ids.GenerateTestID()
		startTime     = genesistest.DefaultValidatorStartTime
		endTime       = startTime.Add(24 * time.Hour)
		pk            = sk.PublicKey()
		primaryStaker = &state.Staker{
			TxID:            ids.GenerateTestID(),
			NodeID:          ids.GenerateTestNodeID(),
			PublicKey:       pk,
			ChainID:         constants.PrimaryNetworkID,
			Weight:          1,
			StartTime:       startTime,
			EndTime:         endTime,
			PotentialReward: 1,
		}
		chainStaker = &state.Staker{
			TxID:      ids.GenerateTestID(),
			NodeID:    primaryStaker.NodeID,
			PublicKey: nil, // inherited from primaryStaker
			ChainID:   chainID,
			Weight:    1,
			StartTime: upgradeTime,
			EndTime:   endTime,
		}
	)

	// Add a chain staker during the Etna upgrade
	{
		blk, err := block.NewBanffStandardBlock(upgradeTime, s.GetLastAccepted(), 1, nil)
		require.NoError(err)

		s.SetHeight(blk.Height())
		s.SetTimestamp(blk.Timestamp())
		s.AddStatelessBlock(blk)
		s.SetLastAccepted(blk.ID())

		require.NoError(s.PutCurrentValidator(primaryStaker))
		require.NoError(s.PutCurrentValidator(chainStaker))

		require.NoError(s.Commit())
	}

	// Remove a chain staker
	{
		blk, err := block.NewBanffStandardBlock(s.GetTimestamp(), s.GetLastAccepted(), 2, nil)
		require.NoError(err)

		s.SetHeight(blk.Height())
		s.SetTimestamp(blk.Timestamp())
		s.AddStatelessBlock(blk)
		s.SetLastAccepted(blk.ID())

		s.DeleteCurrentValidator(chainStaker)

		require.NoError(s.Commit())
	}

	m := NewManager(
		config.Internal{
			Validators: vdrs,
		},
		s,
		metrics.Noop,
		new(mockable.Clock),
	)

	expectedValidators := []map[ids.NodeID]*validators.GetValidatorOutput{
		{}, // Net staker didn't exist at genesis
		{
			chainStaker.NodeID: {
				NodeID:    chainStaker.NodeID,
				PublicKey: bls.PublicKeyToUncompressedBytes(pk),
				Light:     chainStaker.Weight, // Light is kept in sync with Weight
				Weight:    chainStaker.Weight,
				TxID:      chainStaker.TxID,
			},
		}, // Net staker was added at height 1
		{}, // Net staker was removed at height 2
	}
	for height, expected := range expectedValidators {
		actual, err := m.GetValidatorSet(context.Background(), uint64(height), chainID)
		require.NoError(err)
		require.Equal(expected, actual)
	}
}
