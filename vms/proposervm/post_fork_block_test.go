// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package proposervm

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"

	"github.com/luxfi/consensus"
	consensusblock "github.com/luxfi/consensus/engine/chain/block"
	validators "github.com/luxfi/consensus/validator"
	"github.com/luxfi/timer/mockable"
	componentblocktest "github.com/luxfi/vm/chain/blocktest"
	"github.com/luxfi/vm/vms/proposervm/block"
	"github.com/luxfi/vm/vms/proposervm/lp181"
	"github.com/luxfi/vm/vms/proposervm/proposer"
)

var (
	errDuplicateVerify          = errors.New("duplicate verify")
	errUnexpectedBlockRejection = errors.New("unexpected block rejection")
)

// ErrNotOracle is returned when trying to get options from a non-oracle block

// ProposerBlock Option interface tests section
func TestOracle_PostForkBlock_ImplementsInterface(t *testing.T) {
	require := require.New(t)

	// setup
	proBlk := postForkBlock{
		postForkCommonComponents: postForkCommonComponents{
			innerBlk: componentblocktest.BuildChild(componentblocktest.Genesis),
		},
	}

	// test
	_, err := proBlk.Options(context.Background())
	require.Equal(errNotOracle, err)

	// setup
	var (
		activationTime = time.Unix(0, 0)
		durangoTime    = activationTime
	)
	_, _, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	innerTestBlock := componentblocktest.BuildChild(componentblocktest.Genesis)
	innerOracleBlk := &TestOptionsBlock{
		Block: *innerTestBlock,
		opts: [2]*componentblocktest.Block{
			componentblocktest.BuildChild(innerTestBlock),
			componentblocktest.BuildChild(innerTestBlock),
		},
	}

	slb, err := block.Build(
		ids.Empty, // refer unknown parent
		time.Time{},
		0, // pChainHeight,
		block.Epoch{},
		proVM.StakingCertLeaf,
		innerOracleBlk.Bytes(),
		proVM.ctx.ChainID,
		proVM.StakingLeafSigner,
	)
	require.NoError(err)
	proBlk = postForkBlock{
		SignedBlock: slb,
		postForkCommonComponents: postForkCommonComponents{
			vm:       proVM,
			innerBlk: innerOracleBlk,
		},
	}

	// test
	_, err = proBlk.Options(context.Background())
	require.NoError(err)
}

// ProposerBlock.Verify tests section
func TestBlockVerify_PostForkBlock_PreDurango_ParentChecks(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = time.Unix(0, 0)
		durangoTime    = mockable.MaxTime // pre Durango
	)
	coreVM, valState, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	pChainHeight := uint64(100)
	valState.GetCurrentHeightF = func(context.Context) (uint64, error) {
		return pChainHeight, nil
	}

	// create parent block ...
	parentCoreBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	coreVM.BuildBlockF = func(context.Context) (consensusblock.Block, error) {
		return parentCoreBlk, nil
	}
	coreVM.GetBlockF = func(_ context.Context, blkID ids.ID) (consensusblock.Block, error) {
		switch blkID {
		case componentblocktest.GenesisID:
			return componentblocktest.Genesis, nil
		case parentCoreBlk.ID():
			return parentCoreBlk, nil
		default:
			return nil, database.ErrNotFound
		}
	}
	coreVM.ParseBlockF = func(_ context.Context, b []byte) (consensusblock.Block, error) {
		switch {
		case bytes.Equal(b, componentblocktest.GenesisBytes):
			return componentblocktest.Genesis, nil
		case bytes.Equal(b, parentCoreBlk.Bytes()):
			return parentCoreBlk, nil
		default:
			return nil, errUnknownBlock
		}
	}

	parentBlk, err := proVM.BuildBlock(context.Background())
	require.NoError(err)

	require.NoError(parentBlk.Verify(context.Background()))
	require.NoError(proVM.SetPreference(context.Background(), parentBlk.ID()))

	// .. create child block ...
	childCoreBlk := componentblocktest.BuildChild(parentCoreBlk)
	childBlk := postForkBlock{
		postForkCommonComponents: postForkCommonComponents{
			vm:       proVM,
			innerBlk: childCoreBlk,
		},
	}

	// set proVM to be able to build unsigned blocks
	proVM.Set(proVM.Time().Add(proposer.MaxVerifyDelay))

	{
		// child block referring unknown parent does not verify
		childSlb, err := block.BuildUnsigned(
			ids.Empty, // refer unknown parent
			proVM.Time(),
			pChainHeight,
			block.Epoch{},
			childCoreBlk.Bytes(),
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		err = childBlk.Verify(context.Background())
		// The verification fails first at getBlock (parent not found in database)
		// before reaching the inner parent ID check
		require.ErrorIs(err, database.ErrNotFound)
	}

	{
		// child block referring known parent does verify
		childSlb, err := block.BuildUnsigned(
			parentBlk.ID(), // refer known parent
			proVM.Time(),
			pChainHeight,
			block.Epoch{},
			childCoreBlk.Bytes(),
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		require.NoError(childBlk.Verify(context.Background()))
	}
}

func TestBlockVerify_PostForkBlock_PostDurango_ParentChecks(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = time.Unix(0, 0)
		durangoTime    = activationTime // post Durango
	)
	coreVM, valState, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	pChainHeight := uint64(100)
	valState.GetCurrentHeightF = func(context.Context) (uint64, error) {
		return pChainHeight, nil
	}

	parentCoreBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	childCoreBlk := componentblocktest.BuildChild(parentCoreBlk)
	coreVM.BuildBlockF = func(context.Context) (consensusblock.Block, error) {
		return parentCoreBlk, nil
	}
	coreVM.GetBlockF = func(_ context.Context, blkID ids.ID) (consensusblock.Block, error) {
		switch blkID {
		case componentblocktest.GenesisID:
			return componentblocktest.Genesis, nil
		case parentCoreBlk.ID():
			return parentCoreBlk, nil
		case childCoreBlk.ID():
			return childCoreBlk, nil
		default:
			return nil, database.ErrNotFound
		}
	}
	coreVM.ParseBlockF = func(_ context.Context, b []byte) (consensusblock.Block, error) {
		switch {
		case bytes.Equal(b, componentblocktest.GenesisBytes):
			return componentblocktest.Genesis, nil
		case bytes.Equal(b, parentCoreBlk.Bytes()):
			return parentCoreBlk, nil
		case bytes.Equal(b, childCoreBlk.Bytes()):
			return childCoreBlk, nil
		default:
			return nil, errUnknownBlock
		}
	}

	parentBlk, err := proVM.BuildBlock(context.Background())
	require.NoError(err)

	require.NoError(parentBlk.Verify(context.Background()))
	require.NoError(proVM.SetPreference(context.Background(), parentBlk.ID()))
	childBlk := postForkBlock{
		postForkCommonComponents: postForkCommonComponents{
			vm:       proVM,
			innerBlk: childCoreBlk,
		},
	}

	require.NoError(waitForProposerWindow(proVM, parentBlk, parentBlk.(*postForkBlock).PChainHeight()))
	parentPChainHeight := parentBlk.(*postForkBlock).PChainHeight()
	nextEpoch := lp181.NewEpoch(
		proVM.Upgrades,
		parentPChainHeight,
		block.Epoch{},
		parentBlk.Timestamp(),
		proVM.Time(),
	)

	{
		// child block referring unknown parent does not verify
		childSlb, err := block.Build(
			ids.Empty, // refer unknown parent
			proVM.Time(),
			pChainHeight,
			nextEpoch,
			proVM.StakingCertLeaf,
			childCoreBlk.Bytes(),
			proVM.ctx.ChainID,
			proVM.StakingLeafSigner,
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		err = childBlk.Verify(context.Background())
		// The verification fails first at getBlock (parent not found in database)
		// before reaching the inner parent ID check
		require.ErrorIs(err, database.ErrNotFound)
	}

	{
		// child block referring known parent does verify
		childSlb, err := block.Build(
			parentBlk.ID(),
			proVM.Time(),
			pChainHeight,
			nextEpoch,
			proVM.StakingCertLeaf,
			childCoreBlk.Bytes(),
			proVM.ctx.ChainID,
			proVM.StakingLeafSigner,
		)

		require.NoError(err)
		childBlk.SignedBlock = childSlb

		proVM.Set(childSlb.Timestamp())
		require.NoError(childBlk.Verify(context.Background()))
	}
}

func TestBlockVerify_PostForkBlock_TimestampChecks(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = time.Unix(0, 0)
		durangoTime    = mockable.MaxTime
	)
	coreVM, valState, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	// reduce validator state to allow proVM.ctx.NodeID to be easily selected as proposer
	valState.GetValidatorSetF = func(context.Context, uint64, ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
		var (
			thisNode = proVM.ctx.NodeID
			nodeID1  = ids.BuildTestNodeID([]byte{1})
		)
		return map[ids.NodeID]*validators.GetValidatorOutput{
			thisNode: {
				NodeID: thisNode,
				Weight: 5,
			},
			nodeID1: {
				NodeID: nodeID1,
				Weight: 100,
			},
		}, nil
	}
	// Validator state is properly initialized through initTestProposerVM

	pChainHeight := uint64(100)
	valState.GetCurrentHeightF = func(context.Context) (uint64, error) {
		return pChainHeight, nil
	}

	// create parent block ...
	parentCoreBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	coreVM.BuildBlockF = func(context.Context) (consensusblock.Block, error) {
		return parentCoreBlk, nil
	}
	coreVM.GetBlockF = func(_ context.Context, blkID ids.ID) (consensusblock.Block, error) {
		switch blkID {
		case componentblocktest.GenesisID:
			return componentblocktest.Genesis, nil
		case parentCoreBlk.ID():
			return parentCoreBlk, nil
		default:
			return nil, database.ErrNotFound
		}
	}
	coreVM.ParseBlockF = func(_ context.Context, b []byte) (consensusblock.Block, error) {
		switch {
		case bytes.Equal(b, componentblocktest.GenesisBytes):
			return componentblocktest.Genesis, nil
		case bytes.Equal(b, parentCoreBlk.Bytes()):
			return parentCoreBlk, nil
		default:
			return nil, errUnknownBlock
		}
	}

	parentBlk, err := proVM.BuildBlock(context.Background())
	require.NoError(err)

	require.NoError(parentBlk.Verify(context.Background()))
	require.NoError(proVM.SetPreference(context.Background(), parentBlk.ID()))

	var (
		parentTimestamp    = parentBlk.Timestamp()
		parentPChainHeight = parentBlk.(*postForkBlock).PChainHeight()
	)

	childCoreBlk := componentblocktest.BuildChild(parentCoreBlk)
	childBlk := postForkBlock{
		postForkCommonComponents: postForkCommonComponents{
			vm:       proVM,
			innerBlk: childCoreBlk,
		},
	}

	{
		// child block timestamp cannot be lower than parent timestamp
		newTime := parentTimestamp.Add(-1 * time.Second)
		proVM.Clock.Set(newTime)

		childSlb, err := block.Build(
			parentBlk.ID(),
			newTime,
			pChainHeight,
			block.Epoch{},
			proVM.StakingCertLeaf,
			childCoreBlk.Bytes(),
			proVM.ctx.ChainID,
			proVM.StakingLeafSigner,
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		err = childBlk.Verify(context.Background())
		require.ErrorIs(err, errTimeNotMonotonic)
	}

	blkWinDelay, err := proVM.Delay(context.Background(), childCoreBlk.Height(), parentPChainHeight, proVM.ctx.NodeID, proposer.MaxVerifyWindows)
	require.NoError(err)

	// Only test "before window" if delay > 1 second (node is not first proposer)
	if blkWinDelay > time.Second {
		// block cannot arrive before its creator window starts
		beforeWinStart := parentTimestamp.Add(blkWinDelay).Add(-1 * time.Second)
		proVM.Clock.Set(beforeWinStart)

		childSlb, err := block.Build(
			parentBlk.ID(),
			beforeWinStart,
			pChainHeight,
			block.Epoch{},
			proVM.StakingCertLeaf,
			childCoreBlk.Bytes(),
			proVM.ctx.ChainID,
			proVM.StakingLeafSigner,
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		err = childBlk.Verify(context.Background())
		require.ErrorIs(err, errProposerWindowNotStarted)
	}
	// If blkWinDelay == 0, skip test (node is first proposer, no window to test before)

	{
		// block can arrive at its creator window starts
		atWindowStart := parentTimestamp.Add(blkWinDelay)
		proVM.Clock.Set(atWindowStart)

		childSlb, err := block.Build(
			parentBlk.ID(),
			atWindowStart,
			pChainHeight,
			block.Epoch{},
			proVM.StakingCertLeaf,
			childCoreBlk.Bytes(),
			proVM.ctx.ChainID,
			proVM.StakingLeafSigner,
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		require.NoError(childBlk.Verify(context.Background()))
	}

	{
		// block can arrive after its creator window starts
		afterWindowStart := parentTimestamp.Add(blkWinDelay).Add(5 * time.Second)
		proVM.Clock.Set(afterWindowStart)

		childSlb, err := block.Build(
			parentBlk.ID(),
			afterWindowStart,
			pChainHeight,
			block.Epoch{},
			proVM.StakingCertLeaf,
			childCoreBlk.Bytes(),
			proVM.ctx.ChainID,
			proVM.StakingLeafSigner,
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		require.NoError(childBlk.Verify(context.Background()))
	}

	{
		// block can arrive within submission window
		atSubWindowEnd := proVM.Time().Add(proposer.MaxVerifyDelay)
		proVM.Clock.Set(atSubWindowEnd)

		childSlb, err := block.BuildUnsigned(
			parentBlk.ID(),
			atSubWindowEnd,
			pChainHeight,
			block.Epoch{},
			childCoreBlk.Bytes(),
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		require.NoError(childBlk.Verify(context.Background()))
	}

	{
		// block timestamp cannot be too much in the future
		afterSubWinEnd := proVM.Time().Add(maxSkew).Add(time.Second)

		childSlb, err := block.Build(
			parentBlk.ID(),
			afterSubWinEnd,
			pChainHeight,
			block.Epoch{},
			proVM.StakingCertLeaf,
			childCoreBlk.Bytes(),
			proVM.ctx.ChainID,
			proVM.StakingLeafSigner,
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		err = childBlk.Verify(context.Background())
		require.ErrorIs(err, errTimeTooAdvanced)
	}
}

func TestBlockVerify_PostForkBlock_PChainHeightChecks(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = time.Unix(0, 0)
		durangoTime    = activationTime
	)
	coreVM, valState, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	pChainHeight := uint64(100)
	valState.GetCurrentHeightF = func(context.Context) (uint64, error) {
		return pChainHeight, nil
	}

	// create parent block ...
	parentCoreBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	coreVM.BuildBlockF = func(context.Context) (consensusblock.Block, error) {
		return parentCoreBlk, nil
	}
	coreVM.GetBlockF = func(_ context.Context, blkID ids.ID) (consensusblock.Block, error) {
		switch blkID {
		case componentblocktest.GenesisID:
			return componentblocktest.Genesis, nil
		case parentCoreBlk.ID():
			return parentCoreBlk, nil
		default:
			return nil, database.ErrNotFound
		}
	}
	coreVM.ParseBlockF = func(_ context.Context, b []byte) (consensusblock.Block, error) {
		switch {
		case bytes.Equal(b, componentblocktest.GenesisBytes):
			return componentblocktest.Genesis, nil
		case bytes.Equal(b, parentCoreBlk.Bytes()):
			return parentCoreBlk, nil
		default:
			return nil, errUnknownBlock
		}
	}

	parentBlk, err := proVM.BuildBlock(context.Background())
	require.NoError(err)

	require.NoError(parentBlk.Verify(context.Background()))
	require.NoError(proVM.SetPreference(context.Background(), parentBlk.ID()))

	// set VM to be ready to build next block. We set it to generate unsigned blocks
	// for simplicity.
	parentBlkPChainHeight := parentBlk.(*postForkBlock).PChainHeight()
	require.NoError(waitForProposerWindow(proVM, parentBlk, parentBlkPChainHeight))

	childCoreBlk := componentblocktest.BuildChild(parentCoreBlk)
	childBlk := postForkBlock{
		postForkCommonComponents: postForkCommonComponents{
			vm:       proVM,
			innerBlk: childCoreBlk,
		},
	}

	nextEpoch := lp181.NewEpoch(
		proVM.Upgrades,
		parentBlkPChainHeight,
		block.Epoch{},
		parentBlk.Timestamp(),
		proVM.Time(),
	)

	{
		// child P-Chain height must not precede parent P-Chain height
		childSlb, err := block.Build(
			parentBlk.ID(),
			proVM.Time(),
			parentBlkPChainHeight-1,
			nextEpoch,
			proVM.StakingCertLeaf,
			childCoreBlk.Bytes(),
			proVM.ctx.ChainID,
			proVM.StakingLeafSigner,
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		err = childBlk.Verify(context.Background())
		require.ErrorIs(err, errPChainHeightNotMonotonic)
	}

	{
		// child P-Chain height can be equal to parent P-Chain height
		childSlb, err := block.Build(
			parentBlk.ID(),
			proVM.Time(),
			parentBlkPChainHeight,
			nextEpoch,
			proVM.StakingCertLeaf,
			childCoreBlk.Bytes(),
			proVM.ctx.ChainID,
			proVM.StakingLeafSigner,
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		require.NoError(childBlk.Verify(context.Background()))
	}

	{
		// child P-Chain height may follow parent P-Chain height
		childSlb, err := block.Build(
			parentBlk.ID(),
			proVM.Time(),
			parentBlkPChainHeight,
			nextEpoch,
			proVM.StakingCertLeaf,
			childCoreBlk.Bytes(),
			proVM.ctx.ChainID,
			proVM.StakingLeafSigner,
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		require.NoError(childBlk.Verify(context.Background()))
	}

	currPChainHeight, _ := valState.GetCurrentHeightF(context.Background())
	{
		// block P-Chain height can be equal to current P-Chain height
		childSlb, err := block.Build(
			parentBlk.ID(),
			proVM.Time(),
			currPChainHeight,
			nextEpoch,
			proVM.StakingCertLeaf,
			childCoreBlk.Bytes(),
			proVM.ctx.ChainID,
			proVM.StakingLeafSigner,
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		require.NoError(childBlk.Verify(context.Background()))
	}

	{
		// block P-Chain height cannot be at higher than current P-Chain height
		childSlb, err := block.Build(
			parentBlk.ID(),
			proVM.Time(),
			currPChainHeight*2,
			nextEpoch,
			proVM.StakingCertLeaf,
			childCoreBlk.Bytes(),
			proVM.ctx.ChainID,
			proVM.StakingLeafSigner,
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		err = childBlk.Verify(context.Background())
		require.ErrorIs(err, errPChainHeightNotReached)
	}
}

func TestBlockVerify_PostForkBlockBuiltOnOption_PChainHeightChecks(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = time.Unix(0, 0)
		durangoTime    = mockable.MaxTime
	)
	coreVM, valState, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	// Set consensus state to Bootstrapping to skip P-chain height validation
	// This allows testing that child P-chain height can be parent+1 during sync
	proVM.consensusState = uint32(consensus.Bootstrapping)

	pChainHeight := uint64(100)
	valState.GetCurrentHeightF = func(context.Context) (uint64, error) {
		return pChainHeight, nil
	}

	// create post fork oracle block ...
	innerTestBlock := componentblocktest.BuildChild(componentblocktest.Genesis)
	oracleCoreBlk := &TestOptionsBlock{
		Block: *innerTestBlock,
	}
	preferredOracleBlkChild := componentblocktest.BuildChild(innerTestBlock)
	oracleCoreBlk.opts = [2]*componentblocktest.Block{
		preferredOracleBlkChild,
		componentblocktest.BuildChild(innerTestBlock),
	}

	coreVM.BuildBlockF = func(context.Context) (consensusblock.Block, error) {
		return oracleCoreBlk, nil
	}
	coreVM.GetBlockF = func(_ context.Context, blkID ids.ID) (consensusblock.Block, error) {
		switch blkID {
		case componentblocktest.GenesisID:
			return componentblocktest.Genesis, nil
		case oracleCoreBlk.ID():
			return oracleCoreBlk, nil
		case oracleCoreBlk.opts[0].ID():
			return oracleCoreBlk.opts[0], nil
		case oracleCoreBlk.opts[1].ID():
			return oracleCoreBlk.opts[1], nil
		default:
			return nil, database.ErrNotFound
		}
	}
	coreVM.ParseBlockF = func(_ context.Context, b []byte) (consensusblock.Block, error) {
		switch {
		case bytes.Equal(b, componentblocktest.GenesisBytes):
			return componentblocktest.Genesis, nil
		case bytes.Equal(b, oracleCoreBlk.Bytes()):
			return oracleCoreBlk, nil
		case bytes.Equal(b, oracleCoreBlk.opts[0].Bytes()):
			return oracleCoreBlk.opts[0], nil
		case bytes.Equal(b, oracleCoreBlk.opts[1].Bytes()):
			return oracleCoreBlk.opts[1], nil
		default:
			return nil, errUnknownBlock
		}
	}

	oracleBlk, err := proVM.BuildBlock(context.Background())
	require.NoError(err)

	require.NoError(oracleBlk.Verify(context.Background()))
	require.NoError(proVM.SetPreference(context.Background(), oracleBlk.ID()))

	// retrieve one option and verify block built on it
	require.IsType(&postForkBlock{}, oracleBlk)
	postForkOracleBlk := oracleBlk.(*postForkBlock)
	opts, err := postForkOracleBlk.Options(context.Background())
	require.NoError(err)
	parentBlk := opts[0]

	require.NoError(parentBlk.Verify(context.Background()))
	require.NoError(proVM.SetPreference(context.Background(), parentBlk.ID()))

	// set VM to be ready to build next block. We set it to generate unsigned blocks
	// for simplicity.
	nextTime := parentBlk.Timestamp().Add(proposer.MaxVerifyDelay)
	proVM.Set(nextTime)

	parentBlkPChainHeight := postForkOracleBlk.PChainHeight() // option takes proposal blocks' Pchain height

	childCoreBlk := componentblocktest.BuildChild(preferredOracleBlkChild)
	childBlk := postForkBlock{
		postForkCommonComponents: postForkCommonComponents{
			vm:       proVM,
			innerBlk: childCoreBlk,
		},
	}

	{
		// child P-Chain height must not precede parent P-Chain height
		childSlb, err := block.BuildUnsigned(
			parentBlk.ID(),
			nextTime,
			parentBlkPChainHeight-1,
			block.Epoch{},
			childCoreBlk.Bytes(),
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		err = childBlk.Verify(context.Background())
		require.ErrorIs(err, errPChainHeightNotMonotonic)
	}

	{
		// child P-Chain height can be equal to parent P-Chain height
		childSlb, err := block.BuildUnsigned(
			parentBlk.ID(),
			nextTime,
			parentBlkPChainHeight,
			block.Epoch{},
			childCoreBlk.Bytes(),
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		require.NoError(childBlk.Verify(context.Background()))
	}

	{
		// child P-Chain height may follow parent P-Chain height
		childSlb, err := block.BuildUnsigned(
			parentBlk.ID(),
			nextTime,
			parentBlkPChainHeight+1,
			block.Epoch{},
			childCoreBlk.Bytes(),
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		require.NoError(childBlk.Verify(context.Background()))
	}

	currPChainHeight, _ := valState.GetCurrentHeightF(context.Background())
	{
		// block P-Chain height can be equal to current P-Chain height
		childSlb, err := block.BuildUnsigned(
			parentBlk.ID(),
			nextTime,
			currPChainHeight,
			block.Epoch{},
			childCoreBlk.Bytes(),
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb

		require.NoError(childBlk.Verify(context.Background()))
	}

	{
		// block P-Chain height cannot be at higher than current P-Chain height
		// Need to set state to Ready for this validation to be active
		proVM.consensusState = uint32(consensus.Ready)
		childSlb, err := block.BuildUnsigned(
			parentBlk.ID(),
			nextTime,
			currPChainHeight*2,
			block.Epoch{},
			childCoreBlk.Bytes(),
		)
		require.NoError(err)
		childBlk.SignedBlock = childSlb
		err = childBlk.Verify(context.Background())
		require.ErrorIs(err, errPChainHeightNotReached)
	}
}

func TestBlockVerify_PostForkBlock_CoreBlockVerifyIsCalledOnce(t *testing.T) {
	require := require.New(t)

	// Verify a block once (in this test by building it).
	// Show that other verify call would not call coreBlk.Verify()
	var (
		activationTime = time.Unix(0, 0)
		durangoTime    = activationTime
	)
	coreVM, valState, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	pChainHeight := uint64(2000)
	valState.GetCurrentHeightF = func(context.Context) (uint64, error) {
		return pChainHeight, nil
	}

	coreBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	coreVM.BuildBlockF = func(context.Context) (consensusblock.Block, error) {
		return coreBlk, nil
	}
	coreVM.GetBlockF = func(_ context.Context, blkID ids.ID) (consensusblock.Block, error) {
		switch blkID {
		case componentblocktest.GenesisID:
			return componentblocktest.Genesis, nil
		case coreBlk.ID():
			return coreBlk, nil
		default:
			return nil, database.ErrNotFound
		}
	}
	coreVM.ParseBlockF = func(_ context.Context, b []byte) (consensusblock.Block, error) {
		switch {
		case bytes.Equal(b, componentblocktest.GenesisBytes):
			return componentblocktest.Genesis, nil
		case bytes.Equal(b, coreBlk.Bytes()):
			return coreBlk, nil
		default:
			return nil, errUnknownBlock
		}
	}

	builtBlk, err := proVM.BuildBlock(context.Background())
	require.NoError(err)

	require.NoError(builtBlk.Verify(context.Background()))

	// set error on coreBlock.Verify and recall Verify()
	// If Verify is cached correctly, this should NOT call coreBlk.Verify again
	// The second verify returns the cached result (success), NOT the error
	coreBlk.ErrV = errDuplicateVerify
	require.NoError(builtBlk.Verify(context.Background()))

	// rebuild a block with the same core block
	pChainHeight++
	_, err = proVM.BuildBlock(context.Background())
	require.NoError(err)
}

// ProposerBlock.Accept tests section
func TestBlockAccept_PostForkBlock_SetsLastAcceptedBlock(t *testing.T) {
	require := require.New(t)

	// setup
	var (
		activationTime = time.Unix(0, 0)
		durangoTime    = activationTime
	)
	coreVM, valState, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	pChainHeight := uint64(2000)
	valState.GetCurrentHeightF = func(context.Context) (uint64, error) {
		return pChainHeight, nil
	}

	coreBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	coreVM.BuildBlockF = func(context.Context) (consensusblock.Block, error) {
		return coreBlk, nil
	}
	coreVM.GetBlockF = func(_ context.Context, blkID ids.ID) (consensusblock.Block, error) {
		switch blkID {
		case componentblocktest.GenesisID:
			return componentblocktest.Genesis, nil
		case coreBlk.ID():
			return coreBlk, nil
		default:
			return nil, database.ErrNotFound
		}
	}
	coreVM.ParseBlockF = func(_ context.Context, b []byte) (consensusblock.Block, error) {
		switch {
		case bytes.Equal(b, componentblocktest.GenesisBytes):
			return componentblocktest.Genesis, nil
		case bytes.Equal(b, coreBlk.Bytes()):
			return coreBlk, nil
		default:
			return nil, errUnknownBlock
		}
	}

	builtBlk, err := proVM.BuildBlock(context.Background())
	require.NoError(err)

	// test
	require.NoError(builtBlk.Accept(context.Background()))

	coreVM.LastAcceptedF = componentblocktest.MakeLastAcceptedBlockF(
		[]*componentblocktest.Block{
			componentblocktest.Genesis,
			coreBlk,
		},
	)
	acceptedID, err := proVM.LastAccepted(context.Background())
	require.NoError(err)
	require.Equal(builtBlk.ID(), acceptedID)
}

func TestBlockAccept_PostForkBlock_TwoProBlocksWithSameCoreBlock_OneIsAccepted(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = time.Unix(0, 0)
		durangoTime    = activationTime
	)
	coreVM, _, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	var minimumHeight uint64

	// generate two blocks with the same core block and store them
	coreBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	coreVM.BuildBlockF = func(context.Context) (consensusblock.Block, error) {
		return coreBlk, nil
	}

	minimumHeight = componentblocktest.GenesisHeight

	proBlk1, err := proVM.BuildBlock(context.Background())
	require.NoError(err)

	// Advance clock by 1 second to ensure proBlk2 gets a different timestamp
	// (and thus a different ID) even though it wraps the same core block
	minimumHeight++
	proVM.Set(proVM.Time().Add(time.Second))

	proBlk2, err := proVM.BuildBlock(context.Background())
	require.NoError(err)
	require.NotEqual(proBlk2.ID(), proBlk1.ID())

	// set proBlk1 as preferred
	require.NoError(proBlk1.Accept(context.Background()))
	require.Equal(componentblocktest.Accepted, coreBlk.Status())

	acceptedID, err := proVM.LastAccepted(context.Background())
	require.NoError(err)
	require.Equal(proBlk1.ID(), acceptedID)
}

// ProposerBlock.Reject tests section
func TestBlockReject_PostForkBlock_InnerBlockIsNotRejected(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = time.Unix(0, 0)
		durangoTime    = activationTime
	)
	coreVM, _, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	coreBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	coreVM.BuildBlockF = func(context.Context) (consensusblock.Block, error) {
		return coreBlk, nil
	}

	sb, err := proVM.BuildBlock(context.Background())
	require.NoError(err)
	require.IsType(&postForkBlock{}, sb)
	proBlk := sb.(*postForkBlock)

	require.NoError(proBlk.Reject(context.Background()))
}

func TestBlockVerify_PostForkBlock_ShouldBePostForkOption(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = time.Unix(0, 0)
		durangoTime    = activationTime
	)
	coreVM, _, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	// create post fork oracle block ...
	coreTestBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	oracleCoreBlk := &TestOptionsBlock{
		Block: *coreTestBlk,
		opts: [2]*componentblocktest.Block{
			componentblocktest.BuildChild(coreTestBlk),
			componentblocktest.BuildChild(coreTestBlk),
		},
	}

	coreVM.BuildBlockF = func(context.Context) (consensusblock.Block, error) {
		return oracleCoreBlk, nil
	}
	coreVM.GetBlockF = func(_ context.Context, blkID ids.ID) (consensusblock.Block, error) {
		switch blkID {
		case componentblocktest.GenesisID:
			return componentblocktest.Genesis, nil
		case oracleCoreBlk.ID():
			return oracleCoreBlk, nil
		case oracleCoreBlk.opts[0].ID():
			return oracleCoreBlk.opts[0], nil
		case oracleCoreBlk.opts[1].ID():
			return oracleCoreBlk.opts[1], nil
		default:
			return nil, database.ErrNotFound
		}
	}
	coreVM.ParseBlockF = func(_ context.Context, b []byte) (consensusblock.Block, error) {
		switch {
		case bytes.Equal(b, componentblocktest.GenesisBytes):
			return componentblocktest.Genesis, nil
		case bytes.Equal(b, oracleCoreBlk.Bytes()):
			return oracleCoreBlk, nil
		case bytes.Equal(b, oracleCoreBlk.opts[0].Bytes()):
			return oracleCoreBlk.opts[0], nil
		case bytes.Equal(b, oracleCoreBlk.opts[1].Bytes()):
			return oracleCoreBlk.opts[1], nil
		default:
			return nil, errUnknownBlock
		}
	}

	parentBlk, err := proVM.BuildBlock(context.Background())
	require.NoError(err)

	require.NoError(parentBlk.Verify(context.Background()))
	require.NoError(proVM.SetPreference(context.Background(), parentBlk.ID()))

	// retrieve options ...
	require.IsType(&postForkBlock{}, parentBlk)
	postForkOracleBlk := parentBlk.(*postForkBlock)
	opts, err := postForkOracleBlk.Options(context.Background())
	require.NoError(err)
	require.IsType(&postForkOption{}, opts[0])

	// ... and verify them the first time
	require.NoError(opts[0].Verify(context.Background()))
	require.NoError(opts[1].Verify(context.Background()))

	// Build the child
	statelessChild, err := block.Build(
		postForkOracleBlk.ID(),
		postForkOracleBlk.Timestamp().Add(proposer.WindowDuration),
		postForkOracleBlk.PChainHeight(),
		block.Epoch{},
		proVM.StakingCertLeaf,
		oracleCoreBlk.opts[0].Bytes(),
		proVM.ctx.ChainID,
		proVM.StakingLeafSigner,
	)
	require.NoError(err)

	invalidChild, err := proVM.ParseBlock(context.Background(), statelessChild.Bytes())
	if err != nil {
		// A failure to parse is okay here
		return
	}

	err = invalidChild.Verify(context.Background())
	require.ErrorIs(err, errUnexpectedBlockType)
}

func TestBlockVerify_PostForkBlock_PChainTooLow(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = time.Unix(0, 0)
		durangoTime    = activationTime
	)
	coreVM, _, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 5)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	coreBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	coreVM.GetBlockF = func(_ context.Context, blkID ids.ID) (consensusblock.Block, error) {
		switch blkID {
		case componentblocktest.GenesisID:
			return componentblocktest.Genesis, nil
		case coreBlk.ID():
			return coreBlk, nil
		default:
			return nil, database.ErrNotFound
		}
	}
	coreVM.ParseBlockF = func(_ context.Context, b []byte) (consensusblock.Block, error) {
		switch {
		case bytes.Equal(b, componentblocktest.GenesisBytes):
			return componentblocktest.Genesis, nil
		case bytes.Equal(b, coreBlk.Bytes()):
			return coreBlk, nil
		default:
			return nil, errUnknownBlock
		}
	}

	statelessChild, err := block.BuildUnsigned(
		componentblocktest.GenesisID,
		componentblocktest.GenesisTimestamp,
		4,
		block.Epoch{},
		coreBlk.Bytes(),
	)
	require.NoError(err)

	invalidChild, err := proVM.ParseBlock(context.Background(), statelessChild.Bytes())
	if err != nil {
		// A failure to parse is okay here
		return
	}

	err = invalidChild.Verify(context.Background())
	require.ErrorIs(err, errPChainHeightTooLow)
}
