// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package proposervm

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/luxfi/mock/gomock"
	"github.com/stretchr/testify/require"

	consensuscontext "github.com/luxfi/consensus/context"
	consensusblockmock "github.com/luxfi/consensus/engine/chain/block/blockmock"
	consensustest "github.com/luxfi/consensus/test/helpers"
	validatorsmock "github.com/luxfi/consensus/validator/validatorsmock"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/timer/mockable"
	componentblocktest "github.com/luxfi/vm/chain/blocktest"

	engineBlock "github.com/luxfi/consensus/engine/chain/block"
	statelessblock "github.com/luxfi/vm/vms/proposervm/block"
)

// Moved to post_fork_option_test.go to avoid redeclaration

// oracleBlock defines the interface for blocks that provide options
// Note: chain.OracleBlock doesn't exist in consensus package, so we define locally
type oracleBlock interface {
	engineBlock.Block
	Options(context.Context) ([2]engineBlock.Block, error)
}

// Note: validatorStateAdapter is defined in batched_vm_test.go

func TestOracle_PreForkBlkImplementsInterface(t *testing.T) {
	require := require.New(t)

	// setup
	proBlk := preForkBlock{
		Block: componentblocktest.BuildChild(componentblocktest.Genesis),
	}

	// test
	_, err := proBlk.Options(context.Background())
	require.Equal(errNotOracle, err)

	// setup
	proBlk = preForkBlock{
		Block: &TestOptionsBlock{},
	}

	// test
	_, err = proBlk.Options(context.Background())
	require.NoError(err)
}

func TestOracle_PreForkBlkCanBuiltOnPreForkOption(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = mockable.MaxTime
		durangoTime    = activationTime
	)
	coreVM, _, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	// create pre fork oracle block ...
	coreTestBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	preferredTestBlk := componentblocktest.BuildChild(coreTestBlk)
	oracleCoreBlk := &TestOptionsBlock{
		Block: *coreTestBlk,
		opts: [2]*componentblocktest.Block{
			preferredTestBlk,
			componentblocktest.BuildChild(coreTestBlk),
		},
	}

	coreVM.BuildBlockF = func(context.Context) (engineBlock.Block, error) {
		return oracleCoreBlk, nil
	}
	coreVM.GetBlockF = func(_ context.Context, blkID ids.ID) (engineBlock.Block, error) {
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

	parentBlk, err := proVM.BuildBlock(context.Background())
	require.NoError(err)

	// retrieve options ...
	require.IsType(&preForkBlock{}, parentBlk)
	preForkOracleBlk := parentBlk.(*preForkBlock)
	opts, err := preForkOracleBlk.Options(context.Background())
	require.NoError(err)
	require.NoError(opts[0].Verify(context.Background()))

	// ... show a block can be built on top of an option
	require.NoError(proVM.SetPreference(context.Background(), opts[0].ID()))

	lastCoreBlk := &TestOptionsBlock{
		Block: *componentblocktest.BuildChild(preferredTestBlk),
	}
	coreVM.BuildBlockF = func(context.Context) (engineBlock.Block, error) {
		return lastCoreBlk, nil
	}

	preForkChild, err := proVM.BuildBlock(context.Background())
	require.NoError(err)
	require.IsType(&preForkBlock{}, preForkChild)
}

func TestOracle_PostForkBlkCanBuiltOnPreForkOption(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = componentblocktest.GenesisTimestamp.Add(10 * time.Second)
		durangoTime    = activationTime
	)
	coreVM, _, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	// create pre fork oracle block pre activation time...
	coreTestBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	coreTestBlk.TimestampV = activationTime.Add(-1 * time.Second)

	// ... whose options are post activation time
	preferredBlk := componentblocktest.BuildChild(coreTestBlk)
	preferredBlk.TimestampV = activationTime.Add(time.Second)

	unpreferredBlk := componentblocktest.BuildChild(coreTestBlk)
	unpreferredBlk.TimestampV = activationTime.Add(time.Second)

	oracleCoreBlk := &TestOptionsBlock{
		Block: *coreTestBlk,
		opts: [2]*componentblocktest.Block{
			preferredBlk,
			unpreferredBlk,
		},
	}

	coreVM.BuildBlockF = func(context.Context) (engineBlock.Block, error) {
		return oracleCoreBlk, nil
	}
	coreVM.GetBlockF = func(_ context.Context, blkID ids.ID) (engineBlock.Block, error) {
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

	parentBlk, err := proVM.BuildBlock(context.Background())
	require.NoError(err)

	// retrieve options ...
	require.IsType(&preForkBlock{}, parentBlk)
	preForkOracleBlk := parentBlk.(*preForkBlock)
	opts, err := preForkOracleBlk.Options(context.Background())
	require.NoError(err)
	require.NoError(opts[0].Verify(context.Background()))

	// ... show a block can be built on top of an option
	require.NoError(proVM.SetPreference(context.Background(), opts[0].ID()))

	lastCoreBlk := &TestOptionsBlock{
		Block: *componentblocktest.BuildChild(preferredBlk),
	}
	coreVM.BuildBlockF = func(context.Context) (engineBlock.Block, error) {
		return lastCoreBlk, nil
	}

	postForkChild, err := proVM.BuildBlock(context.Background())
	require.NoError(err)
	require.IsType(&postForkBlock{}, postForkChild)
}

func TestBlockVerify_PreFork_ParentChecks(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = componentblocktest.GenesisTimestamp.Add(10 * time.Second)
		durangoTime    = activationTime
	)
	coreVM, _, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	// create parent block ...
	parentCoreBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	coreVM.BuildBlockF = func(context.Context) (engineBlock.Block, error) {
		return parentCoreBlk, nil
	}
	coreVM.GetBlockF = func(_ context.Context, blkID ids.ID) (engineBlock.Block, error) {
		switch blkID {
		case componentblocktest.GenesisID:
			return componentblocktest.Genesis, nil
		case parentCoreBlk.ID():
			return parentCoreBlk, nil
		default:
			return nil, database.ErrNotFound
		}
	}
	coreVM.ParseBlockF = func(_ context.Context, b []byte) (engineBlock.Block, error) {
		switch {
		case bytes.Equal(b, componentblocktest.GenesisBytes):
			return componentblocktest.Genesis, nil
		case bytes.Equal(b, parentCoreBlk.Bytes()):
			return parentCoreBlk, nil
		default:
			return nil, database.ErrNotFound
		}
	}

	parentBlk, err := proVM.BuildBlock(context.Background())
	require.NoError(err)

	// .. create child block ...
	childCoreBlk := componentblocktest.BuildChild(parentCoreBlk)
	childBlk := preForkBlock{
		Block: childCoreBlk,
		vm:    proVM,
	}

	{
		// child block referring unknown parent does not verify
		unknownID := ids.GenerateTestID()
		childCoreBlk.ParentV = unknownID
		err = childBlk.Verify(context.Background())
		require.ErrorIs(err, database.ErrNotFound)
	}

	{
		// child block referring known parent does verify
		childCoreBlk.ParentV = parentBlk.ID()
		require.NoError(childBlk.Verify(context.Background()))
	}
}

func TestBlockVerify_BlocksBuiltOnPreForkGenesis(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = componentblocktest.GenesisTimestamp.Add(10 * time.Second)
		durangoTime    = activationTime
	)
	coreVM, _, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	preActivationTime := activationTime.Add(-1 * time.Second)
	proVM.Set(preActivationTime)

	coreBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	coreBlk.TimestampV = preActivationTime
	coreVM.BuildBlockF = func(context.Context) (engineBlock.Block, error) {
		return coreBlk, nil
	}

	// preFork block verifies if parent is before fork activation time
	preForkChild, err := proVM.BuildBlock(context.Background())
	require.NoError(err)
	require.IsType(&preForkBlock{}, preForkChild)

	require.NoError(preForkChild.Verify(context.Background()))

	// postFork block does NOT verify if parent is before fork activation time
	postForkStatelessChild, err := statelessblock.Build(
		componentblocktest.GenesisID,
		coreBlk.Timestamp(),
		0,                      // pChainHeight
		statelessblock.Epoch{}, // Empty epoch
		proVM.StakingCertLeaf,
		coreBlk.Bytes(),
		proVM.ctx.ChainID,
		proVM.StakingLeafSigner,
	)
	require.NoError(err)
	postForkChild := &postForkBlock{
		SignedBlock: postForkStatelessChild,
		postForkCommonComponents: postForkCommonComponents{
			vm:       proVM,
			innerBlk: coreBlk,
		},
	}

	require.True(postForkChild.Timestamp().Before(activationTime))
	err = postForkChild.Verify(context.Background())
	require.ErrorIs(err, errProposersNotActivated)

	// once activation time is crossed postForkBlock are produced
	postActivationTime := activationTime.Add(time.Second)
	proVM.Set(postActivationTime)

	coreVM.SetPreferenceF = func(context.Context, ids.ID) error {
		return nil
	}
	require.NoError(proVM.SetPreference(context.Background(), preForkChild.ID()))

	secondCoreBlk := componentblocktest.BuildChild(coreBlk)
	secondCoreBlk.TimestampV = postActivationTime
	coreVM.BuildBlockF = func(context.Context) (engineBlock.Block, error) {
		return secondCoreBlk, nil
	}
	coreVM.GetBlockF = func(_ context.Context, id ids.ID) (engineBlock.Block, error) {
		switch id {
		case componentblocktest.GenesisID:
			return componentblocktest.Genesis, nil
		case coreBlk.ID():
			return coreBlk, nil
		default:
			require.FailNow("attempt to get unknown block")
			return nil, nil
		}
	}

	lastPreForkBlk, err := proVM.BuildBlock(context.Background())
	require.NoError(err)
	require.IsType(&preForkBlock{}, lastPreForkBlk)

	require.NoError(lastPreForkBlk.Verify(context.Background()))

	require.NoError(proVM.SetPreference(context.Background(), lastPreForkBlk.ID()))
	thirdCoreBlk := componentblocktest.BuildChild(secondCoreBlk)
	coreVM.BuildBlockF = func(context.Context) (engineBlock.Block, error) {
		return thirdCoreBlk, nil
	}
	coreVM.GetBlockF = func(_ context.Context, id ids.ID) (engineBlock.Block, error) {
		switch id {
		case componentblocktest.GenesisID:
			return componentblocktest.Genesis, nil
		case coreBlk.ID():
			return coreBlk, nil
		case secondCoreBlk.ID():
			return secondCoreBlk, nil
		default:
			require.FailNow("attempt to get unknown block")
			return nil, nil
		}
	}

	firstPostForkBlk, err := proVM.BuildBlock(context.Background())
	require.NoError(err)
	require.IsType(&postForkBlock{}, firstPostForkBlk)

	require.NoError(firstPostForkBlk.Verify(context.Background()))
}

func TestBlockVerify_BlocksBuiltOnPostForkGenesis(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = componentblocktest.GenesisTimestamp.Add(-1 * time.Second)
		durangoTime    = activationTime
	)
	coreVM, _, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	proVM.Set(activationTime)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	// build parent block after fork activation time ...
	coreBlock := componentblocktest.BuildChild(componentblocktest.Genesis)
	coreVM.BuildBlockF = func(context.Context) (engineBlock.Block, error) {
		return coreBlock, nil
	}

	// postFork block verifies if parent is after fork activation time
	postForkChild, err := proVM.BuildBlock(context.Background())
	require.NoError(err)
	require.IsType(&postForkBlock{}, postForkChild)

	require.NoError(postForkChild.Verify(context.Background()))

	// preFork block does NOT verify if parent is after fork activation time
	preForkChild := preForkBlock{
		Block: coreBlock,
		vm:    proVM,
	}
	err = preForkChild.Verify(context.Background())
	require.ErrorIs(err, errUnexpectedBlockType)
}

func TestBlockAccept_PreFork_SetsLastAcceptedBlock(t *testing.T) {
	require := require.New(t)

	// setup
	var (
		activationTime = mockable.MaxTime
		durangoTime    = activationTime
	)
	coreVM, _, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	coreBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	coreVM.BuildBlockF = func(context.Context) (engineBlock.Block, error) {
		return coreBlk, nil
	}
	coreVM.GetBlockF = func(_ context.Context, blkID ids.ID) (engineBlock.Block, error) {
		switch blkID {
		case componentblocktest.GenesisID:
			return componentblocktest.Genesis, nil
		case coreBlk.ID():
			return coreBlk, nil
		default:
			return nil, database.ErrNotFound
		}
	}
	coreVM.ParseBlockF = func(_ context.Context, b []byte) (engineBlock.Block, error) {
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

// ProposerBlock.Reject tests section
func TestBlockReject_PreForkBlock_InnerBlockIsRejected(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = mockable.MaxTime
		durangoTime    = activationTime
	)
	coreVM, _, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	coreBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	coreVM.BuildBlockF = func(context.Context) (engineBlock.Block, error) {
		return coreBlk, nil
	}

	sb, err := proVM.BuildBlock(context.Background())
	require.NoError(err)
	require.IsType(&preForkBlock{}, sb)
	proBlk := sb.(*preForkBlock)

	require.NoError(proBlk.Reject(context.Background()))
	require.Equal(consensustest.Rejected, coreBlk.Status())
}

func TestBlockVerify_ForkBlockIsOracleBlock(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = componentblocktest.GenesisTimestamp.Add(10 * time.Second)
		durangoTime    = activationTime
	)
	coreVM, _, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	postActivationTime := activationTime.Add(time.Second)
	proVM.Set(postActivationTime)

	coreTestBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	coreTestBlk.TimestampV = postActivationTime
	coreBlk := &TestOptionsBlock{
		Block: *coreTestBlk,
		opts: [2]*componentblocktest.Block{
			componentblocktest.BuildChild(coreTestBlk),
			componentblocktest.BuildChild(coreTestBlk),
		},
	}

	coreVM.GetBlockF = func(_ context.Context, blkID ids.ID) (engineBlock.Block, error) {
		switch blkID {
		case componentblocktest.GenesisID:
			return componentblocktest.Genesis, nil
		case coreBlk.ID():
			return coreBlk, nil
		case coreBlk.opts[0].ID():
			return coreBlk.opts[0], nil
		case coreBlk.opts[1].ID():
			return coreBlk.opts[1], nil
		default:
			return nil, database.ErrNotFound
		}
	}
	coreVM.ParseBlockF = func(_ context.Context, b []byte) (engineBlock.Block, error) {
		switch {
		case bytes.Equal(b, componentblocktest.GenesisBytes):
			return componentblocktest.Genesis, nil
		case bytes.Equal(b, coreBlk.Bytes()):
			return coreBlk, nil
		case bytes.Equal(b, coreBlk.opts[0].Bytes()):
			return coreBlk.opts[0], nil
		case bytes.Equal(b, coreBlk.opts[1].Bytes()):
			return coreBlk.opts[1], nil
		default:
			return nil, errUnknownBlock
		}
	}

	firstBlock, err := proVM.ParseBlock(context.Background(), coreBlk.Bytes())
	require.NoError(err)

	require.NoError(firstBlock.Verify(context.Background()))

	oracleBlk, ok := firstBlock.(oracleBlock)
	require.True(ok)

	options, err := oracleBlk.Options(context.Background())
	require.NoError(err)

	require.NoError(options[0].Verify(context.Background()))

	require.NoError(options[1].Verify(context.Background()))
}

func TestBlockVerify_ForkBlockIsOracleBlockButChildrenAreSigned(t *testing.T) {
	require := require.New(t)

	var (
		activationTime = componentblocktest.GenesisTimestamp.Add(10 * time.Second)
		durangoTime    = activationTime
	)
	coreVM, _, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	postActivationTime := activationTime.Add(time.Second)
	proVM.Set(postActivationTime)

	coreTestBlk := componentblocktest.BuildChild(componentblocktest.Genesis)
	coreTestBlk.TimestampV = postActivationTime
	coreBlk := &TestOptionsBlock{
		Block: *coreTestBlk,
		opts: [2]*componentblocktest.Block{
			componentblocktest.BuildChild(coreTestBlk),
			componentblocktest.BuildChild(coreTestBlk),
		},
	}

	coreVM.GetBlockF = func(_ context.Context, blkID ids.ID) (engineBlock.Block, error) {
		switch blkID {
		case componentblocktest.GenesisID:
			return componentblocktest.Genesis, nil
		case coreBlk.ID():
			return coreBlk, nil
		case coreBlk.opts[0].ID():
			return coreBlk.opts[0], nil
		case coreBlk.opts[1].ID():
			return coreBlk.opts[1], nil
		default:
			return nil, database.ErrNotFound
		}
	}
	coreVM.ParseBlockF = func(_ context.Context, b []byte) (engineBlock.Block, error) {
		switch {
		case bytes.Equal(b, componentblocktest.GenesisBytes):
			return componentblocktest.Genesis, nil
		case bytes.Equal(b, coreBlk.Bytes()):
			return coreBlk, nil
		case bytes.Equal(b, coreBlk.opts[0].Bytes()):
			return coreBlk.opts[0], nil
		case bytes.Equal(b, coreBlk.opts[1].Bytes()):
			return coreBlk.opts[1], nil
		default:
			return nil, errUnknownBlock
		}
	}

	firstBlock, err := proVM.ParseBlock(context.Background(), coreBlk.Bytes())
	require.NoError(err)

	require.NoError(firstBlock.Verify(context.Background()))

	// Since this is a child of pre-fork oracle block transition, it should be unsigned
	// but we're intentionally building it as signed to test error handling
	slb, err := statelessblock.Build(
		firstBlock.ID(), // refer to parent
		firstBlock.Timestamp(),
		0,                      // pChainHeight,
		statelessblock.Epoch{}, // Empty epoch
		proVM.StakingCertLeaf,
		coreBlk.opts[0].Bytes(),
		proVM.ctx.ChainID,
		proVM.StakingLeafSigner,
	)
	require.NoError(err)

	invalidChild, err := proVM.ParseBlock(context.Background(), slb.Bytes())
	if err != nil {
		// A failure to parse is okay here
		return
	}

	err = invalidChild.Verify(context.Background())
	// The verification should fail because signed blocks can't be children of pre-fork blocks
	require.ErrorIs(err, errChildOfPreForkBlockHasProposer)
}

// Assert that when the underlying VM implements ChainVMWithBuildBlockContext
// and the proposervm is activated, we only call the VM's BuildBlockWithContext
// when a P-chain height can be correctly provided from the parent block.
func TestPreForkBlock_BuildBlockWithContext(t *testing.T) {
	require := require.New(t)
	ctrl := gomock.NewController(t)

	pChainHeight := uint64(1337)
	blkID := ids.GenerateTestID()
	innerBlk := consensusblockmock.NewMockBlock(ctrl)
	innerBlk.EXPECT().ID().Return(blkID).AnyTimes()
	innerBlk.EXPECT().Timestamp().Return(mockable.MaxTime)
	builtBlk := consensusblockmock.NewMockBlock(ctrl)
	builtBlk.EXPECT().Bytes().Return([]byte{1, 2, 3}).AnyTimes()
	builtBlk.EXPECT().ID().Return(ids.GenerateTestID()).AnyTimes()
	builtBlk.EXPECT().Height().Return(pChainHeight).AnyTimes()

	innerVM := consensusblockmock.NewMockChainVM(ctrl)

	// Create BuildBlockWithContext VM mock
	innerBlockBuilderVM := consensusblockmock.NewMockBuildBlockWithContextVM(ctrl)
	innerBlockBuilderVM.EXPECT().BuildBlockWithContext(gomock.Any(), gomock.Any()).Return(builtBlk, nil).AnyTimes()

	// Create mock validator state to avoid nil pointer dereference
	valState := validatorsmock.NewState(ctrl)
	valState.EXPECT().GetCurrentHeight(gomock.Any()).Return(pChainHeight, nil).AnyTimes()

	// Create minimal consensus context for testing
	consensusCtx := &consensuscontext.Context{
		NetworkID:      1,
		ChainID:        ids.GenerateTestID(),
		NodeID:         ids.GenerateTestNodeID(),
		ValidatorState: valState,
	}

	vm := &VM{
		ChainVM:        innerVM,
		blockBuilderVM: innerBlockBuilderVM,
		ctx:            consensusCtx,
		validatorState: valState,
		logger:         log.NewNoOpLogger(),
	}

	blk := &preForkBlock{
		Block: innerBlk,
		vm:    vm,
	}

	// Should call BuildBlockWithContext since VM supports it (pre-fork, so no P-chain height)
	gotChild, err := blk.buildChild(context.Background())
	require.NoError(err)
	require.Equal(builtBlk, gotChild.(*postForkBlock).innerBlk)

	// Should call BuildBlockWithContext since proposervm is not activated
	innerBlk.EXPECT().Timestamp().Return(time.Time{})
	vm.Upgrades.ApricotPhase4Time = mockable.MaxTime

	gotChild, err = blk.buildChild(context.Background())
	require.NoError(err)
	require.Equal(builtBlk, gotChild.(*preForkBlock).Block)
}
