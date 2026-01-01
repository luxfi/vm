// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package blocktest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

// VM is a test VM that can be used for testing
type VM struct {
	T *testing.T

	InitializeF         func(context.Context, interface{}, interface{}, []byte, []byte, []byte, interface{}, []interface{}, interface{}) error
	BuildBlockF         func(context.Context) (block.Block, error)
	ParseBlockF         func(context.Context, []byte) (block.Block, error)
	GetBlockF           func(context.Context, ids.ID) (block.Block, error)
	LastAcceptedF       func(context.Context) (ids.ID, error)
	SetPreferenceF      func(context.Context, ids.ID) error
	SetStateF           func(context.Context, uint32) error
	VerifyHeightIndexF  func(context.Context) error
	GetBlockIDAtHeightF func(context.Context, uint64) (ids.ID, error)
	GetStatelessBlockF  func(context.Context, ids.ID) (block.Block, error)
}

// ChainVM is a type alias for VM to maintain compatibility
type ChainVM = VM

// BatchedVM is a test VM that supports batch operations
type BatchedVM struct {
	T *testing.T

	GetAncestorsF       func(context.Context, ids.ID, int, int, time.Duration) ([][]byte, error)
	BatchedParseBlockF  func(context.Context, [][]byte) ([]block.Block, error)
	GetBlockIDAtHeightF func(context.Context, uint64) (ids.ID, error)
}

// StateSyncableVM is a test VM that supports state sync
type StateSyncableVM struct {
	T *testing.T

	StateSyncEnabledF           func(context.Context) (bool, error)
	GetOngoingSyncStateSummaryF func(context.Context) (block.StateSummary, error)
	GetLastStateSummaryF        func(context.Context) (block.StateSummary, error)
	ParseStateSummaryF          func(context.Context, []byte) (block.StateSummary, error)
	GetStateSummaryF            func(context.Context, uint64) (block.StateSummary, error)
}

// Standard method implementations - these can be overridden by setting the F fields

func (vm *VM) Initialize(ctx context.Context, chainCtx interface{}, db interface{}, genesisBytes []byte, upgradeBytes []byte, configBytes []byte, msgSender interface{}, validators []interface{}, registry interface{}) error {
	if vm.InitializeF != nil {
		return vm.InitializeF(ctx, chainCtx, db, genesisBytes, upgradeBytes, configBytes, msgSender, validators, registry)
	}
	return nil
}

func (vm *VM) BuildBlock(ctx context.Context) (block.Block, error) {
	if vm.BuildBlockF != nil {
		return vm.BuildBlockF(ctx)
	}
	return nil, errors.New("not implemented")
}

func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (block.Block, error) {
	if vm.ParseBlockF != nil {
		return vm.ParseBlockF(ctx, blockBytes)
	}
	return nil, errors.New("not implemented")
}

func (vm *VM) GetBlock(ctx context.Context, blkID ids.ID) (block.Block, error) {
	if vm.GetBlockF != nil {
		return vm.GetBlockF(ctx, blkID)
	}
	return nil, errors.New("not implemented")
}

func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	if vm.LastAcceptedF != nil {
		return vm.LastAcceptedF(ctx)
	}
	return ids.Empty, nil
}

func (vm *VM) SetPreference(ctx context.Context, blkID ids.ID) error {
	if vm.SetPreferenceF != nil {
		return vm.SetPreferenceF(ctx, blkID)
	}
	return nil
}

func (vm *VM) SetState(ctx context.Context, state uint32) error {
	if vm.SetStateF != nil {
		return vm.SetStateF(ctx, state)
	}
	return nil
}

func (vm *VM) VerifyHeightIndex(ctx context.Context) error {
	if vm.VerifyHeightIndexF != nil {
		return vm.VerifyHeightIndexF(ctx)
	}
	return nil
}

func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	if vm.GetBlockIDAtHeightF != nil {
		return vm.GetBlockIDAtHeightF(ctx, height)
	}
	return ids.Empty, database.ErrNotFound
}

func (vm *VM) GetStatelessBlock(ctx context.Context, blkID ids.ID) (block.Block, error) {
	if vm.GetStatelessBlockF != nil {
		return vm.GetStatelessBlockF(ctx, blkID)
	}
	return nil, errors.New("not implemented")
}

// Connected is called when the node connects to a peer
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion interface{}) error {
	// No-op implementation for tests
	return nil
}

// Disconnected is called when the node disconnects from a peer
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	// No-op implementation for tests
	return nil
}

// HealthCheck returns the health status of the VM
func (vm *VM) HealthCheck(ctx context.Context) (interface{}, error) {
	// Return healthy status for tests
	return map[string]string{"status": "healthy"}, nil
}

// NewHTTPHandler returns an HTTP handler for the VM
func (vm *VM) NewHTTPHandler(ctx context.Context) (interface{}, error) {
	// Return nil handler for tests
	return nil, nil
}

// Shutdown shuts down the VM
func (vm *VM) Shutdown(ctx context.Context) error {
	// No-op implementation for tests
	return nil
}

// Version returns the version of the VM
func (vm *VM) Version(ctx context.Context) (string, error) {
	// Return test version
	return "test-1.0.0", nil
}

// WaitForEvent waits for an event from the VM
func (vm *VM) WaitForEvent(ctx context.Context) (interface{}, error) {
	// No-op implementation for tests
	return nil, nil
}

// BatchedVM methods

func (vm *BatchedVM) GetAncestors(ctx context.Context, blkID ids.ID, maxBlocksNum int, maxBlocksSize int, maxBlocksRetrievalTime time.Duration) ([][]byte, error) {
	if vm.GetAncestorsF != nil {
		return vm.GetAncestorsF(ctx, blkID, maxBlocksNum, maxBlocksSize, maxBlocksRetrievalTime)
	}
	return nil, errors.New("not implemented")
}

func (vm *BatchedVM) BatchedParseBlock(ctx context.Context, blks [][]byte) ([]block.Block, error) {
	if vm.BatchedParseBlockF != nil {
		return vm.BatchedParseBlockF(ctx, blks)
	}
	return nil, errors.New("not implemented")
}

func (vm *BatchedVM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	if vm.GetBlockIDAtHeightF != nil {
		return vm.GetBlockIDAtHeightF(ctx, height)
	}
	return ids.Empty, database.ErrNotFound
}

// StateSyncableVM methods

func (vm *StateSyncableVM) StateSyncEnabled(ctx context.Context) (bool, error) {
	if vm.StateSyncEnabledF != nil {
		return vm.StateSyncEnabledF(ctx)
	}
	return false, nil
}

func (vm *StateSyncableVM) GetOngoingSyncStateSummary(ctx context.Context) (block.StateSummary, error) {
	if vm.GetOngoingSyncStateSummaryF != nil {
		return vm.GetOngoingSyncStateSummaryF(ctx)
	}
	return nil, database.ErrNotFound
}

func (vm *StateSyncableVM) GetLastStateSummary(ctx context.Context) (block.StateSummary, error) {
	if vm.GetLastStateSummaryF != nil {
		return vm.GetLastStateSummaryF(ctx)
	}
	return nil, database.ErrNotFound
}

func (vm *StateSyncableVM) ParseStateSummary(ctx context.Context, summaryBytes []byte) (block.StateSummary, error) {
	if vm.ParseStateSummaryF != nil {
		return vm.ParseStateSummaryF(ctx, summaryBytes)
	}
	return nil, errors.New("not implemented")
}

func (vm *StateSyncableVM) GetStateSummary(ctx context.Context, height uint64) (block.StateSummary, error) {
	if vm.GetStateSummaryF != nil {
		return vm.GetStateSummaryF(ctx, height)
	}
	return nil, database.ErrNotFound
}

// StateSummary is a test state summary that implements block.StateSummary
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
	return block.StateSyncStatic, nil
}
