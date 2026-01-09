// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package proposervm

// Imports commented out as all tests are currently disabled
// import (
// 	"context"
// 	"testing"
// 	"time"
//
// 	"github.com/stretchr/testify/require"
//
// 	"github.com/luxfi/consensus"
// 	consensustest "github.com/luxfi/consensus/test/helpers"
// 	"github.com/luxfi/vm/components/chain/blocktest"
// 	"github.com/luxfi/consensus"
// 	"github.com/luxfi/database"
// 	"github.com/luxfi/database/memdb"
// 	"github.com/luxfi/database/prefixdb"
// )

// func TestProposerVMInitializeShouldFailIfInnerVMCantVerifyItsHeightIndex(t *testing.T) {
// 	require := require.New(t)

// 	customError := errors.New("custom error")
// 	innerVM := &fullVM{
// 		VM: &blocktest.VM{
// 			VerifyHeightIndexF: func(_ context.Context) error {
// 				return customError
// 			},
// 		},
// 	}

// 	innerVM.InitializeF = func(context.Context, context.Context, database.Database,
// 		[]byte, []byte, []byte,
// 		[]*core.Fx, core.AppSender,
// 	) error {
// 		return nil
// 	}

// 	proVM := New(
// 		innerVM,
// 		Config{
// 			ActivationTime:      time.Time{},
// 			DurangoTime:         time.Time{},
// 			MinimumPChainHeight: 0,
// 			MinBlkDelay:         DefaultMinBlockDelay,
// 			NumHistoricalBlocks: DefaultNumHistoricalBlocks,
// 			StakingLeafSigner:   pTestSigner,
// 			StakingCertLeaf:     pTestCert,
// 		},
// 	)
// 	defer func() {
// 		// avoids leaking goroutines
// 		require.NoError(proVM.Shutdown(context.Background()))
// 	}()

// 	ctx := consensustest.Context(t, consensustest.CChainID)
// 	initialState := []byte("genesis state")

// 	err := proVM.Initialize(
// 		context.Background(),
// 		ctx,
// 		prefixdb.New([]byte{}, memdb.New()),
// 		initialState,
// 		nil,
// 		nil,
// 		nil,
// 		nil,
// 	)
// 	require.ErrorIs(customError, err)
// }
