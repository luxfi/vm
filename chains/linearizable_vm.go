// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chains

import (
	"context"
	"errors"
	"sync"

	consensusctx "github.com/luxfi/consensus/context"
	"github.com/luxfi/consensus/engine/chain/block"
	consensusvertex "github.com/luxfi/consensus/engine/vertex"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/platformvm/fx"
	"github.com/luxfi/warp"
)

var (
	_ consensusvertex.LinearizableVM = (*initializeOnLinearizeVM)(nil)
	// Note: linearizeOnInitializeVM doesn't need to fully implement block.ChainVM
	// It's a wrapper that transforms Initialize calls into Linearize calls

	// ErrSkipped is returned when a linearizable VM is asked to perform
	// chain VM operations
	ErrSkipped = errors.New("skipped")
)

// initializeOnLinearizeVM transforms the consensus engine's call to Linearize
// into a call to Initialize. This enables the proposervm to be initialized by
// the call to Linearize. This also provides the stopVertexID to the
// linearizeOnInitializeVM.
type initializeOnLinearizeVM struct {
	consensusvertex.DAGVM
	vmToInitialize block.ChainVM
	vmToLinearize  *linearizeOnInitializeVM

	ctx              *consensusctx.Context
	db               database.Database
	genesisBytes     []byte
	upgradeBytes     []byte
	configBytes      []byte
	fxs              []fx.Fx
	appSender        warp.Sender
	toEngine         chan<- block.Message // Channel to notify consensus engine
	waitForLinearize chan struct{}
	linearizeOnce    sync.Once
}

func (vm *initializeOnLinearizeVM) WaitForEvent(ctx context.Context) (block.Message, error) {
	select {
	case <-vm.waitForLinearize:
		msg, err := vm.vmToInitialize.WaitForEvent(ctx)
		if err != nil {
			return block.Message{}, err
		}
		// Type assert the interface{} return to block.Message
		if blockMsg, ok := msg.(block.Message); ok {
			return blockMsg, nil
		}
		return block.Message{}, errors.New("unexpected message type from WaitForEvent")
	case <-ctx.Done():
		return block.Message{}, ctx.Err()
	}
}

func (vm *initializeOnLinearizeVM) Linearize(ctx context.Context, stopVertexID ids.ID, toVertex ids.ID) error {
	vm.vmToLinearize.stopVertexID = stopVertexID
	defer vm.linearizeOnce.Do(func() {
		close(vm.waitForLinearize)
	})

	// Convert []fx.Fx to []interface{}
	fxsInterface := make([]interface{}, len(vm.fxs))
	for i, fxItem := range vm.fxs {
		fxsInterface[i] = fxItem
	}

	// Pass the toEngine channel to the VM so it can notify consensus about pending transactions
	return vm.vmToInitialize.Initialize(
		ctx,
		vm.ctx,
		&dbManagerWrapper{db: vm.db},
		vm.genesisBytes,
		vm.upgradeBytes,
		vm.configBytes,
		vm.toEngine, // toEngine channel for VM to notify consensus
		fxsInterface,
		vm.appSender,
	)
}

// dbManagerWrapper wraps a database.Database to implement block.DBManager
type dbManagerWrapper struct {
	db database.Database
}

func (d *dbManagerWrapper) Current() database.Database {
	return d.db
}

func (d *dbManagerWrapper) Database(id ids.ID) database.Database {
	// For now, just return the current database
	return d.db
}

func (d *dbManagerWrapper) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

// linearizeOnInitializeVM transforms the proposervm's call to Initialize into a
// call to Linearize. This enables the proposervm to provide its toEngine
// channel to the VM that is being linearized.
type linearizeOnInitializeVM struct {
	consensusvertex.LinearizableVMWithEngine
	stopVertexID ids.ID
	toEngine     chan<- block.Message
}

func NewLinearizeOnInitializeVM(vm consensusvertex.LinearizableVMWithEngine, toEngine chan<- block.Message) *linearizeOnInitializeVM {
	return &linearizeOnInitializeVM{
		LinearizableVMWithEngine: vm,
		toEngine:                 toEngine,
	}
}

func (vm *linearizeOnInitializeVM) Initialize(
	ctx context.Context,
	consensusCtx *consensusctx.Context,
	db database.Database,
	genesisBytes []byte,
	upgradeBytes []byte,
	configBytes []byte,
	fxs []fx.Fx,
	appSender warp.Sender,
) error {
	// When Initialize is called, we need to linearize the DAG
	// The stopVertexID should have been set by initializeOnLinearizeVM.Linearize
	if vm.stopVertexID == ids.Empty {
		return errors.New("stopVertexID not set - Linearize must be called first")
	}

	// Get the underlying linearizable VM
	linearizableVM, ok := vm.LinearizableVMWithEngine.(consensusvertex.LinearizableVM)
	if !ok {
		// If it doesn't implement LinearizableVM, try to call Linearize directly via interface
		// This is a fallback for VMs that embed the engine but expose Linearize differently
		return errors.New("VM does not implement LinearizableVM interface")
	}

	// Call Linearize to convert DAG to linear chain at stopVertexID
	// The toEngine channel will be used to signal when linearization is complete
	toVertexID := ids.Empty // Use empty to indicate full linearization
	return linearizableVM.Linearize(ctx, vm.stopVertexID, toVertexID)
}
