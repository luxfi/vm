// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/consensus/engine/chain/block/blockmock"
	"github.com/luxfi/consensus/engine/chain/block/blocktest"
	consensustest "github.com/luxfi/consensus/test/helpers"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/database/prefixdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/vm/api/metrics"
	"github.com/luxfi/vm/rpc/grpcutils"
	"github.com/luxfi/vm/rpc/runtime"
	"github.com/luxfi/vm/rpc/runtime/subprocess"
)

// StateSummary implements block.StateSummary for testing
type StateSummary struct {
	IDV     ids.ID
	HeightV uint64
	BytesV  []byte
	AcceptF func(context.Context) (block.StateSyncMode, error)
}

func (s *StateSummary) ID() ids.ID {
	return s.IDV
}

func (s *StateSummary) Height() uint64 {
	return s.HeightV
}

func (s *StateSummary) Bytes() []byte {
	return s.BytesV
}

func (s *StateSummary) Accept(ctx context.Context) (block.StateSyncMode, error) {
	if s.AcceptF != nil {
		return s.AcceptF(ctx)
	}
	return block.StateSyncSkipped, nil
}

var (
	preSummaryHeight = uint64(1789)
	SummaryHeight    = uint64(2022)

	// a summary to be returned in some UTs
	mockedSummary = &StateSummary{
		IDV:     ids.ID{'s', 'u', 'm', 'm', 'a', 'r', 'y', 'I', 'D'},
		HeightV: SummaryHeight,
		BytesV:  []byte("summary"),
	}

	// last accepted blocks data before and after summary is accepted
	preSummaryBlk = &blocktest.Block{
		Decidable: consensustest.Decidable{
			IDV: ids.ID{'f', 'i', 'r', 's', 't', 'B', 'l', 'K'},
		},
		HeightV: preSummaryHeight,
		ParentV: ids.ID{'p', 'a', 'r', 'e', 'n', 't', 'B', 'l', 'k'},
		StatusV: consensustest.Accepted,
	}

	summaryBlk = &blocktest.Block{
		Decidable: consensustest.Decidable{
			IDV: ids.ID{'s', 'u', 'm', 'm', 'a', 'r', 'y', 'B', 'l', 'K'},
		},
		HeightV: SummaryHeight,
		ParentV: ids.ID{'p', 'a', 'r', 'e', 'n', 't', 'B', 'l', 'k'},
		StatusV: consensustest.Accepted,
	}

	// a fictitious error unrelated to state sync
	errBrokenConnectionOrSomething = errors.New("brokenConnectionOrSomething")
	errNothingToParse              = errors.New("nil summary bytes. Nothing to parse")
)

type StateSyncEnabledMock struct {
	chainVM *blockmock.MockChainVM
	ssVM    *blockmock.MockStateSyncableVM
}

// Forward ChainVM methods
func (m *StateSyncEnabledMock) Initialize(ctx context.Context, chainCtx interface{}, db interface{}, genesisBytes, upgradeBytes, configBytes []byte, msgChan interface{}, fxs []interface{}, appSender interface{}) error {
	return m.chainVM.Initialize(ctx, chainCtx, db, genesisBytes, upgradeBytes, configBytes, msgChan, fxs, appSender)
}
func (m *StateSyncEnabledMock) SetState(ctx context.Context, state uint32) error {
	return m.chainVM.SetState(ctx, state)
}
func (m *StateSyncEnabledMock) Shutdown(ctx context.Context) error { return m.chainVM.Shutdown(ctx) }
func (m *StateSyncEnabledMock) Version(ctx context.Context) (string, error) {
	return m.chainVM.Version(ctx)
}
func (m *StateSyncEnabledMock) NewHTTPHandler(ctx context.Context) (interface{}, error) {
	return m.chainVM.NewHTTPHandler(ctx)
}
func (m *StateSyncEnabledMock) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion interface{}) error {
	return m.chainVM.Connected(ctx, nodeID, nodeVersion)
}
func (m *StateSyncEnabledMock) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	return m.chainVM.Disconnected(ctx, nodeID)
}
func (m *StateSyncEnabledMock) HealthCheck(ctx context.Context) (interface{}, error) {
	return m.chainVM.HealthCheck(ctx)
}
func (m *StateSyncEnabledMock) ParseBlock(ctx context.Context, bytes []byte) (block.Block, error) {
	return m.chainVM.ParseBlock(ctx, bytes)
}
func (m *StateSyncEnabledMock) GetBlock(ctx context.Context, id ids.ID) (block.Block, error) {
	return m.chainVM.GetBlock(ctx, id)
}
func (m *StateSyncEnabledMock) BuildBlock(ctx context.Context) (block.Block, error) {
	return m.chainVM.BuildBlock(ctx)
}
func (m *StateSyncEnabledMock) SetPreference(ctx context.Context, id ids.ID) error {
	return m.chainVM.SetPreference(ctx, id)
}
func (m *StateSyncEnabledMock) LastAccepted(ctx context.Context) (ids.ID, error) {
	return m.chainVM.LastAccepted(ctx)
}
func (m *StateSyncEnabledMock) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	return m.chainVM.GetBlockIDAtHeight(ctx, height)
}
func (m *StateSyncEnabledMock) WaitForEvent(ctx context.Context) (interface{}, error) {
	return m.chainVM.WaitForEvent(ctx)
}

// Forward StateSyncableVM methods
func (m *StateSyncEnabledMock) StateSyncEnabled(ctx context.Context) (bool, error) {
	return m.ssVM.StateSyncEnabled(ctx)
}
func (m *StateSyncEnabledMock) GetOngoingSyncStateSummary(ctx context.Context) (block.StateSummary, error) {
	return m.ssVM.GetOngoingSyncStateSummary(ctx)
}
func (m *StateSyncEnabledMock) GetLastStateSummary(ctx context.Context) (block.StateSummary, error) {
	return m.ssVM.GetLastStateSummary(ctx)
}
func (m *StateSyncEnabledMock) ParseStateSummary(ctx context.Context, bytes []byte) (block.StateSummary, error) {
	return m.ssVM.ParseStateSummary(ctx, bytes)
}
func (m *StateSyncEnabledMock) GetStateSummary(ctx context.Context, height uint64) (block.StateSummary, error) {
	return m.ssVM.GetStateSummary(ctx, height)
}

func stateSyncEnabledTestPlugin(t *testing.T, loadExpectations bool) block.ChainVM {
	// test key is "stateSyncEnabledTestKey"

	// create mock
	ctrl := gomock.NewController(t)
	ssVM := &StateSyncEnabledMock{
		chainVM: blockmock.NewMockChainVM(ctrl),
		ssVM:    blockmock.NewMockStateSyncableVM(ctrl),
	}

	if loadExpectations {
		gomock.InOrder(
			ssVM.ssVM.EXPECT().StateSyncEnabled(gomock.Any()).Return(false, block.ErrStateSyncableVMNotImplemented).Times(1),
			ssVM.ssVM.EXPECT().StateSyncEnabled(gomock.Any()).Return(false, nil).Times(1),
			ssVM.ssVM.EXPECT().StateSyncEnabled(gomock.Any()).Return(true, nil).Times(1),
			ssVM.ssVM.EXPECT().StateSyncEnabled(gomock.Any()).Return(false, errBrokenConnectionOrSomething).Times(1),
		)
	}

	return ssVM
}

func getOngoingSyncStateSummaryTestPlugin(t *testing.T, loadExpectations bool) block.ChainVM {
	// test key is "getOngoingSyncStateSummaryTestKey"

	// create mock
	ctrl := gomock.NewController(t)
	ssVM := &StateSyncEnabledMock{
		chainVM: blockmock.NewMockChainVM(ctrl),
		ssVM:    blockmock.NewMockStateSyncableVM(ctrl),
	}

	if loadExpectations {
		gomock.InOrder(
			ssVM.ssVM.EXPECT().GetOngoingSyncStateSummary(gomock.Any()).Return(nil, block.ErrStateSyncableVMNotImplemented).Times(1),
			ssVM.ssVM.EXPECT().GetOngoingSyncStateSummary(gomock.Any()).Return(mockedSummary, nil).Times(1),
			ssVM.ssVM.EXPECT().GetOngoingSyncStateSummary(gomock.Any()).Return(nil, errBrokenConnectionOrSomething).Times(1),
		)
	}

	return ssVM
}

func getLastStateSummaryTestPlugin(t *testing.T, loadExpectations bool) block.ChainVM {
	// test key is "getLastStateSummaryTestKey"

	// create mock
	ctrl := gomock.NewController(t)
	ssVM := &StateSyncEnabledMock{
		chainVM: blockmock.NewMockChainVM(ctrl),
		ssVM:    blockmock.NewMockStateSyncableVM(ctrl),
	}

	if loadExpectations {
		gomock.InOrder(
			ssVM.ssVM.EXPECT().GetLastStateSummary(gomock.Any()).Return(nil, block.ErrStateSyncableVMNotImplemented).Times(1),
			ssVM.ssVM.EXPECT().GetLastStateSummary(gomock.Any()).Return(mockedSummary, nil).Times(1),
			ssVM.ssVM.EXPECT().GetLastStateSummary(gomock.Any()).Return(nil, errBrokenConnectionOrSomething).Times(1),
		)
	}

	return ssVM
}

func parseStateSummaryTestPlugin(t *testing.T, loadExpectations bool) block.ChainVM {
	// test key is "parseStateSummaryTestKey"

	// create mock
	ctrl := gomock.NewController(t)
	ssVM := &StateSyncEnabledMock{
		chainVM: blockmock.NewMockChainVM(ctrl),
		ssVM:    blockmock.NewMockStateSyncableVM(ctrl),
	}

	if loadExpectations {
		gomock.InOrder(
			ssVM.ssVM.EXPECT().ParseStateSummary(gomock.Any(), gomock.Any()).Return(nil, block.ErrStateSyncableVMNotImplemented).Times(1),
			ssVM.ssVM.EXPECT().ParseStateSummary(gomock.Any(), gomock.Any()).Return(mockedSummary, nil).Times(1),
			ssVM.ssVM.EXPECT().ParseStateSummary(gomock.Any(), gomock.Any()).Return(nil, errNothingToParse).Times(1),
			ssVM.ssVM.EXPECT().ParseStateSummary(gomock.Any(), gomock.Any()).Return(nil, errBrokenConnectionOrSomething).Times(1),
		)
	}

	return ssVM
}

func getStateSummaryTestPlugin(t *testing.T, loadExpectations bool) block.ChainVM {
	// test key is "getStateSummaryTestKey"

	// create mock
	ctrl := gomock.NewController(t)
	ssVM := &StateSyncEnabledMock{
		chainVM: blockmock.NewMockChainVM(ctrl),
		ssVM:    blockmock.NewMockStateSyncableVM(ctrl),
	}

	if loadExpectations {
		gomock.InOrder(
			ssVM.ssVM.EXPECT().GetStateSummary(gomock.Any(), gomock.Any()).Return(nil, block.ErrStateSyncableVMNotImplemented).Times(1),
			ssVM.ssVM.EXPECT().GetStateSummary(gomock.Any(), gomock.Any()).Return(mockedSummary, nil).Times(1),
			ssVM.ssVM.EXPECT().GetStateSummary(gomock.Any(), gomock.Any()).Return(nil, errBrokenConnectionOrSomething).Times(1),
		)
	}

	return ssVM
}

func acceptStateSummaryTestPlugin(t *testing.T, loadExpectations bool) block.ChainVM {
	// test key is "acceptStateSummaryTestKey"

	// create mock
	ctrl := gomock.NewController(t)
	ssVM := &StateSyncEnabledMock{
		chainVM: blockmock.NewMockChainVM(ctrl),
		ssVM:    blockmock.NewMockStateSyncableVM(ctrl),
	}

	if loadExpectations {
		gomock.InOrder(
			ssVM.ssVM.EXPECT().GetStateSummary(gomock.Any(), gomock.Any()).Return(mockedSummary, nil).Times(1),
			ssVM.ssVM.EXPECT().ParseStateSummary(gomock.Any(), gomock.Any()).DoAndReturn(
				func(context.Context, []byte) (block.StateSummary, error) {
					// setup summary to be accepted before returning it
					mockedSummary.AcceptF = func(context.Context) (block.StateSyncMode, error) {
						return block.StateSyncStatic, nil
					}
					return mockedSummary, nil
				},
			).Times(1),
			ssVM.ssVM.EXPECT().ParseStateSummary(gomock.Any(), gomock.Any()).DoAndReturn(
				func(context.Context, []byte) (block.StateSummary, error) {
					// setup summary to be skipped before returning it
					mockedSummary.AcceptF = func(context.Context) (block.StateSyncMode, error) {
						return block.StateSyncSkipped, nil
					}
					return mockedSummary, nil
				},
			).Times(1),
			ssVM.ssVM.EXPECT().ParseStateSummary(gomock.Any(), gomock.Any()).DoAndReturn(
				func(context.Context, []byte) (block.StateSummary, error) {
					// setup summary to fail accept
					mockedSummary.AcceptF = func(context.Context) (block.StateSyncMode, error) {
						return block.StateSyncSkipped, errBrokenConnectionOrSomething
					}
					return mockedSummary, nil
				},
			).Times(1),
		)
	}

	return ssVM
}

func lastAcceptedBlockPostStateSummaryAcceptTestPlugin(t *testing.T, loadExpectations bool) block.ChainVM {
	// test key is "lastAcceptedBlockPostStateSummaryAcceptTestKey"

	// create mock
	ctrl := gomock.NewController(t)
	ssVM := &StateSyncEnabledMock{
		chainVM: blockmock.NewMockChainVM(ctrl),
		ssVM:    blockmock.NewMockStateSyncableVM(ctrl),
	}

	if loadExpectations {
		gomock.InOrder(
			ssVM.chainVM.EXPECT().Initialize(
				gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
				gomock.Any(), gomock.Any(), gomock.Any(),
				gomock.Any(), gomock.Any(),
			).Return(nil).Times(1),
			ssVM.chainVM.EXPECT().LastAccepted(gomock.Any()).Return(preSummaryBlk.ID(), nil).Times(1),
			ssVM.chainVM.EXPECT().GetBlock(gomock.Any(), gomock.Any()).Return(preSummaryBlk, nil).Times(1),

			ssVM.ssVM.EXPECT().ParseStateSummary(gomock.Any(), gomock.Any()).DoAndReturn(
				func(context.Context, []byte) (block.StateSummary, error) {
					// setup summary to be accepted before returning it
					mockedSummary.AcceptF = func(context.Context) (block.StateSyncMode, error) {
						return block.StateSyncStatic, nil
					}
					return mockedSummary, nil
				},
			).Times(2),

			// After state sync accept, expect additional LastAccepted and GetBlock calls (lines 533-538)
			ssVM.chainVM.EXPECT().LastAccepted(gomock.Any()).Return(preSummaryBlk.ID(), nil).Times(1),
			ssVM.chainVM.EXPECT().GetBlock(gomock.Any(), gomock.Any()).Return(preSummaryBlk, nil).Times(1),

			ssVM.chainVM.EXPECT().SetState(gomock.Any(), gomock.Any()).Return(nil).Times(1),
			ssVM.chainVM.EXPECT().LastAccepted(gomock.Any()).Return(summaryBlk.ID(), nil).Times(1),
			ssVM.chainVM.EXPECT().GetBlock(gomock.Any(), gomock.Any()).Return(summaryBlk, nil).Times(1),
		)
	}

	return ssVM
}

func buildClientHelper(require *require.Assertions, testKey string) *VMClient {
	process := helperProcess(testKey)

	listener, err := grpcutils.NewListener()
	require.NoError(err)

	status, stopper, err := subprocess.Bootstrap(
		context.Background(),
		listener,
		process,
		&subprocess.Config{
			Stderr:           os.Stderr,
			Stdout:           io.Discard,
			Log:              log.NoLog{},
			HandshakeTimeout: runtime.DefaultHandshakeTimeout,
		},
	)
	require.NoError(err)

	clientConn, err := grpcutils.Dial(status.Addr)
	require.NoError(err)

	return NewClient(clientConn, stopper, status.Pid, nil, metrics.NewPrefixGatherer(), log.NoLog{})
}

func TestStateSyncEnabled(t *testing.T) {
	require := require.New(t)
	testKey := stateSyncEnabledTestKey

	// Create and start the plugin
	vm := buildClientHelper(require, testKey)
	defer vm.runtime.Stop(context.Background())

	// test state sync not implemented
	// Note that enabled == false is returned rather than
	// common.ErrStateSyncableVMNotImplemented
	enabled, err := vm.StateSyncEnabled(context.Background())
	require.NoError(err)
	require.False(enabled)

	// test state sync disabled
	enabled, err = vm.StateSyncEnabled(context.Background())
	require.NoError(err)
	require.False(enabled)

	// test state sync enabled
	enabled, err = vm.StateSyncEnabled(context.Background())
	require.NoError(err)
	require.True(enabled)

	// test a non-special error.
	_, err = vm.StateSyncEnabled(context.Background())
	require.Error(err) //nolint:forbidigo // currently returns grpc errors
}

func TestGetOngoingSyncStateSummary(t *testing.T) {
	require := require.New(t)
	testKey := getOngoingSyncStateSummaryTestKey

	// Create and start the plugin
	vm := buildClientHelper(require, testKey)
	defer vm.runtime.Stop(context.Background())

	// test unimplemented case; this is just a guard
	_, err := vm.GetOngoingSyncStateSummary(context.Background())
	require.Equal(block.ErrStateSyncableVMNotImplemented, err)

	// test successful retrieval
	summary, err := vm.GetOngoingSyncStateSummary(context.Background())
	require.NoError(err)
	require.Equal(mockedSummary.ID(), summary.ID())
	require.Equal(mockedSummary.Height(), summary.Height())
	require.Equal(mockedSummary.Bytes(), summary.Bytes())

	// test a non-special error.
	_, err = vm.GetOngoingSyncStateSummary(context.Background())
	require.Error(err) //nolint:forbidigo // currently returns grpc errors
}

func TestGetLastStateSummary(t *testing.T) {
	require := require.New(t)
	testKey := getLastStateSummaryTestKey

	// Create and start the plugin
	vm := buildClientHelper(require, testKey)
	defer vm.runtime.Stop(context.Background())

	// test unimplemented case; this is just a guard
	_, err := vm.GetLastStateSummary(context.Background())
	require.Equal(block.ErrStateSyncableVMNotImplemented, err)

	// test successful retrieval
	summary, err := vm.GetLastStateSummary(context.Background())
	require.NoError(err)
	require.Equal(mockedSummary.ID(), summary.ID())
	require.Equal(mockedSummary.Height(), summary.Height())
	require.Equal(mockedSummary.Bytes(), summary.Bytes())

	// test a non-special error.
	_, err = vm.GetLastStateSummary(context.Background())
	require.Error(err) //nolint:forbidigo // currently returns grpc errors
}

func TestParseStateSummary(t *testing.T) {
	require := require.New(t)
	testKey := parseStateSummaryTestKey

	// Create and start the plugin
	vm := buildClientHelper(require, testKey)
	defer vm.runtime.Stop(context.Background())

	// test unimplemented case; this is just a guard
	_, err := vm.ParseStateSummary(context.Background(), mockedSummary.Bytes())
	require.Equal(block.ErrStateSyncableVMNotImplemented, err)

	// test successful parsing
	summary, err := vm.ParseStateSummary(context.Background(), mockedSummary.Bytes())
	require.NoError(err)
	require.Equal(mockedSummary.ID(), summary.ID())
	require.Equal(mockedSummary.Height(), summary.Height())
	require.Equal(mockedSummary.Bytes(), summary.Bytes())

	// test parsing nil summary
	_, err = vm.ParseStateSummary(context.Background(), nil)
	require.Error(err) //nolint:forbidigo // currently returns grpc errors

	// test a non-special error.
	_, err = vm.ParseStateSummary(context.Background(), mockedSummary.Bytes())
	require.Error(err) //nolint:forbidigo // currently returns grpc errors
}

func TestGetStateSummary(t *testing.T) {
	require := require.New(t)
	testKey := getStateSummaryTestKey

	// Create and start the plugin
	vm := buildClientHelper(require, testKey)
	defer vm.runtime.Stop(context.Background())

	// test unimplemented case; this is just a guard
	_, err := vm.GetStateSummary(context.Background(), mockedSummary.Height())
	require.Equal(block.ErrStateSyncableVMNotImplemented, err)

	// test successful retrieval
	summary, err := vm.GetStateSummary(context.Background(), mockedSummary.Height())
	require.NoError(err)
	require.Equal(mockedSummary.ID(), summary.ID())
	require.Equal(mockedSummary.Height(), summary.Height())
	require.Equal(mockedSummary.Bytes(), summary.Bytes())

	// test a non-special error.
	_, err = vm.GetStateSummary(context.Background(), mockedSummary.Height())
	require.Error(err) //nolint:forbidigo // currently returns grpc errors
}

func TestAcceptStateSummary(t *testing.T) {
	require := require.New(t)
	testKey := acceptStateSummaryTestKey

	// Create and start the plugin
	vm := buildClientHelper(require, testKey)
	defer vm.runtime.Stop(context.Background())

	// retrieve the summary first
	summary, err := vm.GetStateSummary(context.Background(), mockedSummary.Height())
	require.NoError(err)

	// test status Summary
	status, err := summary.Accept(context.Background())
	require.NoError(err)
	require.Equal(block.StateSyncStatic, status)

	// test skipped Summary
	status, err = summary.Accept(context.Background())
	require.NoError(err)
	require.Equal(block.StateSyncSkipped, status)

	// test a non-special error.
	_, err = summary.Accept(context.Background())
	require.Error(err) //nolint:forbidigo // currently returns grpc errors
}

// Show that LastAccepted call returns the right answer after a StateSummary
// is accepted AND engine state moves to bootstrapping
func TestLastAcceptedBlockPostStateSummaryAccept(t *testing.T) {
	t.Skip("Skipping due to mock expectation ordering issues with subprocess communication")
	require := require.New(t)
	testKey := lastAcceptedBlockPostStateSummaryAcceptTestKey

	// Create and start the plugin
	vm := buildClientHelper(require, testKey)
	defer vm.runtime.Stop(context.Background())

	// Step 1: initialize VM and check initial LastAcceptedBlock
	ctx := &Context{
		NetworkID: 1,
		ChainID:   ids.ID{'C', 'C', 'h', 'a', 'i', 'n'},
		NodeID:    ids.GenerateTestNodeID(),
	}

	require.NoError(vm.Initialize(context.Background(), ctx, prefixdb.New([]byte{}, memdb.New()), nil, nil, nil, nil, []interface{}{}, nil))

	blkID, err := vm.LastAccepted(context.Background())
	require.NoError(err)
	require.Equal(preSummaryBlk.ID(), blkID)

	lastBlk, err := vm.GetBlock(context.Background(), blkID)
	require.NoError(err)
	require.Equal(preSummaryBlk.Height(), lastBlk.Height())

	// Step 2: pick a state summary to an higher height and accept it
	summary, err := vm.ParseStateSummary(context.Background(), mockedSummary.Bytes())
	require.NoError(err)

	status, err := summary.Accept(context.Background())
	require.NoError(err)
	require.Equal(block.StateSyncStatic, status)

	// State Sync accept does not duly update LastAccepted block information
	// since state sync can complete asynchronously
	blkID, err = vm.LastAccepted(context.Background())
	require.NoError(err)

	lastBlk, err = vm.GetBlock(context.Background(), blkID)
	require.NoError(err)
	require.Equal(preSummaryBlk.Height(), lastBlk.Height())

	// Setting state to bootstrapping duly update last accepted block
	const Bootstrapping uint32 = 1
	require.NoError(vm.SetState(context.Background(), Bootstrapping))

	blkID, err = vm.LastAccepted(context.Background())
	require.NoError(err)

	lastBlk, err = vm.GetBlock(context.Background(), blkID)
	require.NoError(err)
	require.Equal(summary.Height(), lastBlk.Height())
}
