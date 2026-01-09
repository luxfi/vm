// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	consensuscore "github.com/luxfi/consensus/core"
	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	luxvm "github.com/luxfi/vm"

	"github.com/luxfi/version"
	"github.com/luxfi/vm/vms/dexvm/orderbook"
)

// Ensure ChainVM implements block.ChainVM
var _ block.ChainVM = (*ChainVM)(nil)

var (
	errInvalidBlock     = errors.New("invalid block")
	errBlockNotFound    = errors.New("block not found")
	errNoBlocksBuilt    = errors.New("no blocks to build")
	errVMNotInitialized = errors.New("VM not initialized")

	// Genesis block ID (all zeros)
	genesisBlockID = ids.ID{}
)

// ChainVM wraps the functional DEX VM to implement the block.ChainVM interface
// required for running as an L2 subnet plugin.
type ChainVM struct {
	// The inner functional VM
	inner *VM

	// Logger
	log log.Logger

	// Lock for thread safety
	lock sync.RWMutex

	// Block storage
	blocks map[ids.ID]*Block

	// Last accepted block info
	lastAcceptedID     ids.ID
	lastAcceptedHeight uint64

	// Preferred block (tip of the chain we're building on)
	preferredID ids.ID

	// Pending transactions for next block
	pendingTxs [][]byte

	// Block building interval
	blockInterval time.Duration

	// Channel to notify consensus of new blocks
	toEngine chan<- luxvm.Message

	// Initialization state
	initialized bool
}

// NewChainVM creates a new ChainVM that wraps a functional DEX VM
func NewChainVM(logger log.Logger) *ChainVM {
	return &ChainVM{
		inner:         &VM{},
		log:           logger,
		blocks:        make(map[ids.ID]*Block),
		blockInterval: 100 * time.Millisecond, // Default 100ms blocks
	}
}

// Initialize implements the VM interface
func (vm *ChainVM) Initialize(
	ctx context.Context,
	consensusCtx interface{},
	dbManager interface{},
	genesisBytes []byte,
	upgradeBytes []byte,
	configBytes []byte,
	msgChan interface{},
	fxs []interface{},
	appSender interface{},
) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	// Store the message channel
	if ch, ok := msgChan.(chan<- luxvm.Message); ok {
		vm.toEngine = ch
	}

	// Initialize the inner VM
	if err := vm.inner.Initialize(
		ctx,
		consensusCtx,
		dbManager,
		genesisBytes,
		upgradeBytes,
		configBytes,
		msgChan,
		fxs,
		appSender,
	); err != nil {
		return err
	}

	// Set logger for inner VM
	vm.inner.log = vm.log

	// Create genesis block
	genesisBlock := &Block{
		vm:        vm,
		id:        genesisBlockID,
		parentID:  ids.Empty,
		height:    0,
		timestamp: time.Unix(0, 0),
		txs:       nil,
		status:    StatusAccepted,
	}
	vm.blocks[genesisBlockID] = genesisBlock
	vm.lastAcceptedID = genesisBlockID
	vm.lastAcceptedHeight = 0
	vm.preferredID = genesisBlockID

	vm.initialized = true

	if vm.log != nil {
		vm.log.Info("DEX ChainVM initialized",
			"genesisID", genesisBlockID,
		)
	}

	return nil
}

// SetState implements the VM interface
func (vm *ChainVM) SetState(ctx context.Context, state uint32) error {
	return vm.inner.SetState(ctx, state)
}

// Shutdown implements the VM interface
func (vm *ChainVM) Shutdown(ctx context.Context) error {
	return vm.inner.Shutdown(ctx)
}

// Version implements the VM interface
func (vm *ChainVM) Version(ctx context.Context) (string, error) {
	return vm.inner.Version(ctx)
}

// NewHTTPHandler implements the block.ChainVM interface
func (vm *ChainVM) NewHTTPHandler(ctx context.Context) (interface{}, error) {
	return vm.inner.CreateHandlers(ctx)
}

// CreateHandlers implements the interface expected by chain manager for HTTP registration
func (vm *ChainVM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return vm.inner.CreateHandlers(ctx)
}

// HealthCheck implements the VM interface
func (vm *ChainVM) HealthCheck(ctx context.Context) (interface{}, error) {
	return vm.inner.HealthCheck(ctx)
}

// Connected implements the block.ChainVM interface
func (vm *ChainVM) Connected(ctx context.Context, nodeID ids.NodeID, v interface{}) error {
	if ver, ok := v.(*version.Application); ok {
		return vm.inner.Connected(ctx, nodeID, ver)
	}
	return nil
}

// Disconnected implements the VM interface
func (vm *ChainVM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	return vm.inner.Disconnected(ctx, nodeID)
}

// AppGossip implements the VM interface
func (vm *ChainVM) AppGossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error {
	return vm.inner.AppGossip(ctx, nodeID, msg)
}

// AppRequest implements the VM interface
func (vm *ChainVM) AppRequest(ctx context.Context, nodeID ids.NodeID, requestID uint32, deadline time.Time, request []byte) error {
	return vm.inner.AppRequest(ctx, nodeID, requestID, deadline, request)
}

// AppRequestFailed implements the VM interface
func (vm *ChainVM) AppRequestFailed(ctx context.Context, nodeID ids.NodeID, requestID uint32, appErr *consensuscore.AppError) error {
	return vm.inner.AppRequestFailed(ctx, nodeID, requestID, appErr)
}

// AppResponse implements the VM interface
func (vm *ChainVM) AppResponse(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error {
	return vm.inner.AppResponse(ctx, nodeID, requestID, response)
}

// BuildBlock implements the block.ChainVM interface.
// It builds a new block from pending transactions.
func (vm *ChainVM) BuildBlock(ctx context.Context) (block.Block, error) {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if !vm.initialized {
		return nil, errVMNotInitialized
	}

	// Get parent block
	parent, ok := vm.blocks[vm.preferredID]
	if !ok {
		return nil, fmt.Errorf("preferred block not found: %s", vm.preferredID)
	}

	// Create new block
	newHeight := parent.height + 1
	newTimestamp := time.Now()

	// Generate block ID from height and timestamp using sha256
	blockIDBytes := make([]byte, 16)
	binary.BigEndian.PutUint64(blockIDBytes[0:8], newHeight)
	binary.BigEndian.PutUint64(blockIDBytes[8:16], uint64(newTimestamp.UnixNano()))
	hash := sha256.Sum256(blockIDBytes)
	var newID ids.ID
	copy(newID[:], hash[:])

	block := &Block{
		vm:        vm,
		id:        newID,
		parentID:  vm.preferredID,
		height:    newHeight,
		timestamp: newTimestamp,
		txs:       vm.pendingTxs,
		status:    StatusUnknown,
	}

	// Clear pending transactions
	vm.pendingTxs = nil

	// Store the block
	vm.blocks[newID] = block

	if vm.log != nil {
		vm.log.Debug("Built block",
			"id", newID,
			"height", newHeight,
			"txCount", len(block.txs),
		)
	}

	return block, nil
}

// ParseBlock implements the block.ChainVM interface.
// It parses a block from bytes.
func (vm *ChainVM) ParseBlock(ctx context.Context, data []byte) (block.Block, error) {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	block, err := parseBlock(vm, data)
	if err != nil {
		return nil, err
	}

	// Check if we already have this block
	if existingBlock, ok := vm.blocks[block.id]; ok {
		return existingBlock, nil
	}

	// Store the new block
	vm.blocks[block.id] = block

	return block, nil
}

// GetBlock implements the block.ChainVM interface.
// It returns a block by its ID.
func (vm *ChainVM) GetBlock(ctx context.Context, blkID ids.ID) (block.Block, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()

	block, ok := vm.blocks[blkID]
	if !ok {
		return nil, errBlockNotFound
	}

	return block, nil
}

// SetPreference implements the block.ChainVM interface.
// It sets the preferred block for building new blocks.
func (vm *ChainVM) SetPreference(ctx context.Context, blkID ids.ID) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if _, ok := vm.blocks[blkID]; !ok {
		return fmt.Errorf("block not found: %s", blkID)
	}

	vm.preferredID = blkID

	if vm.log != nil {
		vm.log.Debug("Set preference", "blockID", blkID)
	}

	return nil
}

// LastAccepted implements the block.ChainVM interface.
// It returns the ID of the last accepted block.
func (vm *ChainVM) LastAccepted(ctx context.Context) (ids.ID, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()

	return vm.lastAcceptedID, nil
}

// GetBlockIDAtHeight returns the block ID at the given height
func (vm *ChainVM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()

	for id, block := range vm.blocks {
		if block.height == height && block.status == StatusAccepted {
			return id, nil
		}
	}

	return ids.Empty, errBlockNotFound
}

// SubmitTx adds a transaction to the pending pool
func (vm *ChainVM) SubmitTx(tx []byte) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	vm.pendingTxs = append(vm.pendingTxs, tx)

	// Notify consensus that we have pending work
	if vm.toEngine != nil {
		select {
		case vm.toEngine <- luxvm.Message{Type: luxvm.PendingTxs}:
		default:
			// Channel full, skip notification
		}
	}

	return nil
}

// GetInnerVM returns the inner functional VM for direct access
func (vm *ChainVM) GetInnerVM() *VM {
	return vm.inner
}

// Getter methods for DEX functionality

// GetOrderbook returns an orderbook by symbol
func (vm *ChainVM) GetOrderbook(symbol string) (*orderbook.Orderbook, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return vm.inner.GetOrderbook(symbol)
}

// GetLiquidityManager returns the liquidity manager
func (vm *ChainVM) GetLiquidityManager() interface{} {
	return vm.inner.GetLiquidityManager()
}

// GetPerpetualsEngine returns the perpetuals engine
func (vm *ChainVM) GetPerpetualsEngine() interface{} {
	return vm.inner.GetPerpetualsEngine()
}

// WaitForEvent implements the block.ChainVM interface.
// It blocks until an event occurs that should trigger block building.
func (vm *ChainVM) WaitForEvent(ctx context.Context) (interface{}, error) {
	// For now, return nil - block building is triggered via SubmitTx
	// and the PendingTxs message is sent to toEngine
	<-ctx.Done()
	return nil, ctx.Err()
}
