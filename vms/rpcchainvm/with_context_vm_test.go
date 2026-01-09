// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpcchainvm

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/consensus/engine/chain/block/blockmock"
	"github.com/luxfi/consensus/engine/chain/block/blocktest"
	consensustest "github.com/luxfi/consensus/test/helpers"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
)

var (
	testPreSummaryBlk = &blocktest.Block{
		Decidable: consensustest.Decidable{
			IDV:     ids.ID{'f', 'i', 'r', 's', 't', 'B', 'l', 'K'},
			StatusV: 0,
		},
		HeightV: 1789,
		ParentV: ids.ID{'p', 'a', 'r', 'e', 'n', 't', 'B', 'l', 'k'},
		StatusV: consensustest.Accepted,
	}
)

var (
	blockContext = &block.Context{
		PChainHeight: 1,
	}

	blkID    = ids.ID{1}
	parentID = ids.ID{0}
	blkBytes = []byte{0}
)

type ContextEnabledVMMock struct {
	chainVM             *blockmock.MockChainVM
	buildBlockContextVM *blockmock.MockBuildBlockWithContextVM
}

// Ensure ContextEnabledVMMock implements the required interfaces
var (
	_ block.ChainVM                      = (*ContextEnabledVMMock)(nil)
	_ block.BuildBlockWithContextChainVM = (*ContextEnabledVMMock)(nil)
)

// Forward ChainVM methods
func (m *ContextEnabledVMMock) Initialize(ctx context.Context, chainCtx interface{}, db interface{}, genesisBytes, upgradeBytes, configBytes []byte, msgChan interface{}, fxs []interface{}, appSender interface{}) error {
	return m.chainVM.Initialize(ctx, chainCtx, db, genesisBytes, upgradeBytes, configBytes, msgChan, fxs, appSender)
}
func (m *ContextEnabledVMMock) SetState(ctx context.Context, state uint32) error {
	return m.chainVM.SetState(ctx, state)
}
func (m *ContextEnabledVMMock) Shutdown(ctx context.Context) error { return m.chainVM.Shutdown(ctx) }
func (m *ContextEnabledVMMock) Version(ctx context.Context) (string, error) {
	return m.chainVM.Version(ctx)
}
func (m *ContextEnabledVMMock) NewHTTPHandler(ctx context.Context) (interface{}, error) {
	return m.chainVM.NewHTTPHandler(ctx)
}
func (m *ContextEnabledVMMock) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion interface{}) error {
	return m.chainVM.Connected(ctx, nodeID, nodeVersion)
}
func (m *ContextEnabledVMMock) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	return m.chainVM.Disconnected(ctx, nodeID)
}
func (m *ContextEnabledVMMock) HealthCheck(ctx context.Context) (interface{}, error) {
	return m.chainVM.HealthCheck(ctx)
}
func (m *ContextEnabledVMMock) ParseBlock(ctx context.Context, bytes []byte) (block.Block, error) {
	return m.chainVM.ParseBlock(ctx, bytes)
}
func (m *ContextEnabledVMMock) GetBlock(ctx context.Context, id ids.ID) (block.Block, error) {
	return m.chainVM.GetBlock(ctx, id)
}
func (m *ContextEnabledVMMock) BuildBlock(ctx context.Context) (block.Block, error) {
	return m.chainVM.BuildBlock(ctx)
}
func (m *ContextEnabledVMMock) SetPreference(ctx context.Context, id ids.ID) error {
	return m.chainVM.SetPreference(ctx, id)
}
func (m *ContextEnabledVMMock) LastAccepted(ctx context.Context) (ids.ID, error) {
	return m.chainVM.LastAccepted(ctx)
}
func (m *ContextEnabledVMMock) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	return m.chainVM.GetBlockIDAtHeight(ctx, height)
}
func (m *ContextEnabledVMMock) WaitForEvent(ctx context.Context) (interface{}, error) {
	return m.chainVM.WaitForEvent(ctx)
}

// Forward BuildBlockWithContextVM method
func (m *ContextEnabledVMMock) BuildBlockWithContext(ctx context.Context, blockCtx *block.Context) (block.Block, error) {
	return m.buildBlockContextVM.BuildBlockWithContext(ctx, blockCtx)
}

type ContextEnabledBlockMock struct {
	*blockmock.MockBlock
	*blockmock.MockWithVerifyContext
}

func contextEnabledTestPlugin(t *testing.T, loadExpectations bool) block.ChainVM {
	// test key is "contextTestKey"

	// create mock
	ctrl := gomock.NewController(t)
	ctxVM := &ContextEnabledVMMock{
		chainVM:             blockmock.NewMockChainVM(ctrl),
		buildBlockContextVM: blockmock.NewMockBuildBlockWithContextVM(ctrl),
	}

	if loadExpectations {
		ctxBlock := &ContextEnabledBlockMock{
			MockBlock:             blockmock.NewMockBlock(ctrl),
			MockWithVerifyContext: blockmock.NewMockWithVerifyContext(ctrl),
		}
		// Initialize expectations
		ctxVM.chainVM.EXPECT().Initialize(
			gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
		).Return(nil).AnyTimes()
		ctxVM.chainVM.EXPECT().LastAccepted(gomock.Any()).Return(testPreSummaryBlk.ID(), nil).AnyTimes()
		ctxVM.chainVM.EXPECT().GetBlock(gomock.Any(), gomock.Any()).Return(testPreSummaryBlk, nil).AnyTimes()

		// BuildBlockWithContext expectations
		ctxVM.buildBlockContextVM.EXPECT().BuildBlockWithContext(gomock.Any(), gomock.Any()).Return(ctxBlock, nil).AnyTimes()
		ctxBlock.MockWithVerifyContext.EXPECT().ShouldVerifyWithContext(gomock.Any()).Return(true, nil).AnyTimes()
		ctxBlock.MockBlock.EXPECT().ID().Return(blkID).AnyTimes()
		ctxBlock.MockBlock.EXPECT().ParentID().Return(parentID).AnyTimes()
		ctxBlock.MockBlock.EXPECT().Parent().Return(parentID).AnyTimes()
		ctxBlock.MockBlock.EXPECT().Bytes().Return(blkBytes).AnyTimes()
		ctxBlock.MockBlock.EXPECT().Height().Return(uint64(1)).AnyTimes()
		ctxBlock.MockBlock.EXPECT().Timestamp().Return(time.Now()).AnyTimes()

		// VerifyWithContext expectations
		ctxVM.chainVM.EXPECT().ParseBlock(gomock.Any(), blkBytes).Return(ctxBlock, nil).AnyTimes()
		ctxBlock.MockWithVerifyContext.EXPECT().VerifyWithContext(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	}

	return ctxVM
}

func TestContextVMSummary(t *testing.T) {
	require := require.New(t)
	testKey := contextTestKey

	// Create and start the plugin
	vm := buildClientHelper(require, testKey)
	defer vm.runtime.Stop(context.Background())

	ctx := &Context{
		NetworkID: 1,
		ChainID:   ids.ID{'C', 'C', 'h', 'a', 'i', 'n'},
		NodeID:    ids.GenerateTestNodeID(),
	}

	require.NoError(vm.Initialize(context.Background(), ctx, memdb.New(), nil, nil, nil, nil, []interface{}{}, nil))

	blkIntf, err := vm.BuildBlockWithContext(context.Background(), blockContext)
	require.NoError(err)

	blk, ok := blkIntf.(block.WithVerifyContext)
	require.True(ok)

	shouldVerify, err := blk.ShouldVerifyWithContext(context.Background())
	require.NoError(err)
	require.True(shouldVerify)

	require.NoError(blk.VerifyWithContext(context.Background(), blockContext))
}
