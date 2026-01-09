// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package proposervm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/luxfi/log"
	"github.com/luxfi/metric"

	"github.com/luxfi/cache"
	"github.com/luxfi/cache/lru"
	"github.com/luxfi/cache/metercacher"
	"github.com/luxfi/consensus"
	consensuscontext "github.com/luxfi/consensus/context"
	consensusinterfaces "github.com/luxfi/consensus/core/interfaces"
	chainblock "github.com/luxfi/consensus/engine/chain/block"
	validators "github.com/luxfi/consensus/validator"
	"github.com/luxfi/constants"
	"github.com/luxfi/database"
	"github.com/luxfi/database/prefixdb"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/utils/math"
	"github.com/luxfi/vm/utils/timer/mockable"
	"github.com/luxfi/vm/vms"

	"github.com/luxfi/vm/vms/proposervm/proposer"
	"github.com/luxfi/vm/vms/proposervm/state"
	"github.com/luxfi/vm/vms/proposervm/tree"

	statelessblock "github.com/luxfi/vm/vms/proposervm/block"
)

const (
	// DefaultMinBlockDelay should be kept as whole seconds because block
	// timestamps are only specific to the second.
	DefaultMinBlockDelay = time.Second
	// DefaultNumHistoricalBlocks as 0 results in never deleting any historical
	// blocks.
	DefaultNumHistoricalBlocks uint64 = 0

	innerBlkCacheSize = 64 * constants.MiB
)

var (
	_ chainblock.ChainVM         = (*VM)(nil)
	_ chainblock.BatchedChainVM  = (*VM)(nil)
	_ chainblock.StateSyncableVM = (*VM)(nil)

	dbPrefix = []byte("proposervm")
)

func cachedBlockSize(_ ids.ID, blk chainblock.Block) int {
	return ids.IDLen + len(blk.Bytes()) + constants.PointerOverhead
}

type VM struct {
	chainblock.ChainVM
	Config
	blockBuilderVM chainblock.BuildBlockWithContextChainVM
	batchedVM      chainblock.BatchedChainVM
	ssVM           chainblock.StateSyncableVM

	state.State

	proposer.Windower
	tree.Tree
	mockable.Clock

	ctx            *consensuscontext.Context
	db             *versiondb.Database
	logger         log.Logger
	validatorState validators.State
	netIDsCache    cache.Cacher[ids.ID, ids.ID] // chainID -> netID cache for GetNetworkID lookups

	// Block ID --> Block
	// Each element is a block that passed verification but
	// hasn't yet been accepted/rejected
	verifiedBlocks map[ids.ID]PostForkBlock
	// Stateless block ID --> inner block.
	// Only contains post-fork blocks near the tip so that the cache doesn't get
	// filled with random blocks every time this node parses blocks while
	// processing a GetAncestors message from a bootstrapping node.
	innerBlkCache  cache.Cacher[ids.ID, chainblock.Block]
	preferred      ids.ID
	consensusState uint32 // Consensus state: Syncing, Bootstrapping, Ready

	// lastAcceptedTime is set to the last accepted PostForkBlock's timestamp
	// if the last accepted block has been a PostForkOption block since having
	// initialized the VM.
	lastAcceptedTime time.Time

	// lastAcceptedHeight is set to the last accepted PostForkBlock's height.
	lastAcceptedHeight uint64

	// proposerBuildSlotGauge reports the slot index when this node may attempt
	// to build a block.
	proposerBuildSlotGauge metric.Gauge

	// acceptedBlocksSlotHistogram reports the slots that accepted blocks were
	// proposed in.
	acceptedBlocksSlotHistogram metric.Histogram

	// lastAcceptedTimestampGaugeVec reports timestamps for the last-accepted
	// [postForkBlock] and its inner block.
	lastAcceptedTimestampGaugeVec metric.GaugeVec
}

// New performs best when [minBlkDelay] is whole seconds. This is because block
// timestamps are only specific to the second.
func New(
	vm chainblock.ChainVM,
	config Config,
) *VM {
	blockBuilderVM, _ := vm.(chainblock.BuildBlockWithContextChainVM)
	batchedVM, _ := vm.(chainblock.BatchedChainVM)
	ssVM, _ := vm.(chainblock.StateSyncableVM)
	return &VM{
		ChainVM:        vm,
		Config:         config,
		blockBuilderVM: blockBuilderVM,
		batchedVM:      batchedVM,
		ssVM:           ssVM,
	}
}

func (vm *VM) Initialize(
	ctx context.Context,
	chainCtx interface{},
	db interface{},
	genesisBytes []byte,
	upgradeBytes []byte,
	configBytes []byte,
	msgChan interface{},
	fxs []interface{},
	appSender interface{},
) error {
	// Type assert the interface{} parameters to their concrete types
	chainContext := chainCtx.(*consensuscontext.Context)
	vmDB := db.(database.Database)

	// Explicit type conversions for interface{} fields - Rob Pike approach: no hiding complexity
	logger := chainContext.Log.(log.Logger)
	validatorState := chainContext.ValidatorState.(validators.State)

	vm.ctx = chainContext
	vm.logger = logger
	vm.validatorState = validatorState
	vm.db = versiondb.New(prefixdb.New(dbPrefix, vmDB))
	baseState, err := state.NewMetered(vm.db, "state", vm.Config.Registerer)
	if err != nil {
		return err
	}
	vm.State = baseState
	vm.Windower = proposer.New(validatorState, constants.PrimaryNetworkID, chainContext.ChainID)
	vm.Tree = tree.New()
	registry, ok := vm.Config.Registerer.(metric.Registry)
	if !ok {
		return errors.New("registerer must be a Registry")
	}
	metrics := metric.NewWithRegistry("", registry)
	innerBlkCache, err := metercacher.New(
		"inner_block_cache",
		registry,
		lru.NewSizedCache(innerBlkCacheSize, cachedBlockSize),
	)
	if err != nil {
		return err
	}
	vm.innerBlkCache = innerBlkCache

	// Initialize NetID cache for validator state lookups
	vm.netIDsCache = lru.NewCache[ids.ID, ids.ID](4096)

	vm.verifiedBlocks = make(map[ids.ID]PostForkBlock)

	err = vm.ChainVM.Initialize(
		ctx,
		chainCtx,
		db,
		genesisBytes,
		upgradeBytes,
		configBytes,
		msgChan,
		fxs,
		appSender,
	)
	if err != nil {
		return err
	}

	if err := vm.repairAcceptedChainByHeight(ctx); err != nil {
		return fmt.Errorf("failed to repair accepted chain by height: %w", err)
	}

	if err := vm.setLastAcceptedMetadata(ctx); err != nil {
		return fmt.Errorf("failed to set last accepted metadata: %w", err)
	}

	if err := vm.pruneOldBlocks(); err != nil {
		return fmt.Errorf("failed to prune old blocks: %w", err)
	}

	forkHeight, err := vm.GetForkHeight()
	switch err {
	case nil:
		logger.Info("initialized proposervm",
			log.String("state", "after fork"),
			log.Uint64("forkHeight", forkHeight),
			log.Uint64("lastAcceptedHeight", vm.lastAcceptedHeight),
		)
	case database.ErrNotFound:
		logger.Info("initialized proposervm",
			log.String("state", "before fork"),
		)
	default:
		return fmt.Errorf("failed to get fork height: %w", err)
	}

	vm.proposerBuildSlotGauge = metrics.NewGauge(
		"block_building_slot",
		"the slot that this node may attempt to build a block",
	)
	vm.acceptedBlocksSlotHistogram = metrics.NewHistogram(
		"accepted_blocks_slot",
		"the slot accepted blocks were proposed in",
		// define the following ranges:
		// (-inf, 0]
		// (0, 1]
		// (1, 2]
		// (2, inf)
		// the usage of ".5" before was to ensure we work around the limitation
		// of comparing floating point of the same numerical value.
		[]float64{0.5, 1.5, 2.5},
	)
	vm.lastAcceptedTimestampGaugeVec = metrics.NewGaugeVec(
		"last_accepted_timestamp",
		"timestamp of the last block accepted",
		[]string{"block_type"},
	)

	// Metrics are automatically registered by the metrics instance
	return nil
}

// Shutdown ops then propagate shutdown to innerVM
func (vm *VM) Shutdown(ctx context.Context) error {
	if err := vm.db.Commit(); err != nil {
		return err
	}
	// ChainVM doesn't have Shutdown in new consensus
	// return vm.ChainVM.Shutdown(ctx)
	return nil
}

func (vm *VM) SetState(ctx context.Context, newState uint32) error {
	if err := vm.ChainVM.SetState(ctx, newState); err != nil {
		return err
	}

	oldState := vm.consensusState
	vm.consensusState = newState
	if oldState != uint32(consensusinterfaces.Syncing) {
		return nil
	}

	// When finishing StateSyncing, if state sync has failed or was skipped,
	// repairAcceptedChainByHeight rolls back the chain to the previously last
	// accepted block. If state sync has completed successfully, this call is a
	// no-op.
	if err := vm.repairAcceptedChainByHeight(ctx); err != nil {
		return fmt.Errorf("failed to repair accepted chain height: %w", err)
	}
	return vm.setLastAcceptedMetadata(ctx)
}

func (vm *VM) BuildBlock(ctx context.Context) (chainblock.Block, error) {
	preferredBlock, err := vm.getBlock(ctx, vm.preferred)
	if err != nil {
		vm.logger.Error("unexpected build block failure",
			log.String("reason", "failed to fetch preferred block"),
			log.Stringer("parentID", vm.preferred),
			log.Err(err),
		)
		return nil, err
	}

	return preferredBlock.buildChild(ctx)
}

func (vm *VM) ParseBlock(ctx context.Context, b []byte) (chainblock.Block, error) {
	if blk, err := vm.parsePostForkBlock(ctx, b, true); err == nil {
		return blk, nil
	}
	return vm.parsePreForkBlock(ctx, b)
}

func (vm *VM) ParseLocalBlock(ctx context.Context, b []byte) (chainblock.Block, error) {
	if blk, err := vm.parsePostForkBlock(ctx, b, false); err == nil {
		return blk, nil
	}
	return vm.parsePreForkBlock(ctx, b)
}

func (vm *VM) GetBlock(ctx context.Context, id ids.ID) (chainblock.Block, error) {
	return vm.getBlock(ctx, id)
}

func (vm *VM) SetPreference(ctx context.Context, preferred ids.ID) error {
	// Short-circuit if already preferred - no context check needed
	if vm.preferred == preferred {
		return nil
	}

	// Check for context cancellation before any state changes
	if err := ctx.Err(); err != nil {
		return err
	}

	vm.preferred = preferred

	// Check for context cancellation before expensive operations
	if err := ctx.Err(); err != nil {
		return err
	}

	blk, err := vm.getPostForkBlock(ctx, preferred)
	if err != nil {
		return vm.ChainVM.SetPreference(ctx, preferred)
	}

	// Check for context cancellation before delegating to inner VM
	if err := ctx.Err(); err != nil {
		return err
	}

	innerBlkID := blk.getInnerBlk().ID()
	if err := vm.ChainVM.SetPreference(ctx, innerBlkID); err != nil {
		return err
	}

	vm.logger.Debug("set preference",
		log.Stringer("blkID", preferred),
		log.Stringer("innerBlkID", innerBlkID),
	)
	return nil
}

func (vm *VM) WaitForEvent(ctx context.Context) (interface{}, error) {
	for {
		if err := ctx.Err(); err != nil {
			vm.logger.Debug("Aborting WaitForEvent, context is done", log.Err(err))
			return 0, err
		}

		timeToBuild, shouldWait, err := vm.timeToBuild(ctx)
		if err != nil {
			vm.logger.Debug("Aborting WaitForEvent", log.Err(err))
			return 0, err
		}

		// If we are pre-fork or haven't finished bootstrapping yet, we should
		// directly forward the inner VM's events.
		if !shouldWait {
			vm.logger.Debug("Waiting for inner VM event (pre-fork or before normal operation)")
			return vm.ChainVM.WaitForEvent(ctx)
		}

		duration := time.Until(timeToBuild)
		if duration <= 0 {
			vm.logger.Debug("Can build a block without waiting")
			return vm.ChainVM.WaitForEvent(ctx)
		}

		vm.logger.Debug("Waiting until we should build a block", log.Duration("duration", duration))

		// Wait until it is our turn to build a block.
		select {
		case <-ctx.Done():
		case <-time.After(duration):
			// We should not call ChainVM.WaitForEvent here as it is possible
			// that timeToBuild was capped less than the actual time for us to
			// build a block. If it is actually our turn to build, timeToBuild
			// will be <= 0 in the next iteration.
		}
	}
}

func (vm *VM) timeToBuild(ctx context.Context) (time.Time, bool, error) {
	vm.ctx.Lock.Lock()
	defer vm.ctx.Lock.Unlock()

	// Block building is only supported if the consensus state is Ready
	// and the vm is not state syncing.
	//
	// TODO: Correctly handle dynamic state sync here. When the innerVM is
	// dynamically state syncing, we should return here as well.
	if vm.consensusState != uint32(consensus.Ready) {
		return time.Time{}, false, nil
	}

	// Because the VM is marked as being in the Ready state, we know
	// that [VM.SetPreference] must have already been called.
	blk, err := vm.getPostForkBlock(ctx, vm.preferred)
	// If the preferred block is pre-fork, we should wait for events on the
	// innerVM.
	if err != nil {
		return time.Time{}, false, nil
	}

	pChainHeight, err := blk.pChainHeight(ctx)
	if err != nil {
		return time.Time{}, false, err
	}

	var (
		childBlockHeight = blk.Height() + 1
		parentTimestamp  = blk.Timestamp()
		nextStartTime    time.Time
	)
	if vm.Upgrades.IsDurangoActivated(parentTimestamp) {
		currentTime := vm.Clock.Time().Truncate(time.Second)
		if nextStartTime, err = vm.getPostDurangoSlotTime(
			ctx,
			childBlockHeight,
			pChainHeight,
			proposer.TimeToSlot(parentTimestamp, currentTime),
			parentTimestamp,
		); err == nil {
			vm.proposerBuildSlotGauge.Set(float64(proposer.TimeToSlot(parentTimestamp, nextStartTime)))
		}
	} else {
		nextStartTime, err = vm.getPreDurangoSlotTime(
			ctx,
			childBlockHeight,
			pChainHeight,
			parentTimestamp,
		)
	}
	if err != nil {
		vm.logger.Debug("failed to fetch the expected delay",
			log.Err(err),
		)

		// A nil error is returned here because it is possible that
		// bootstrapping caused the last accepted block to move past the latest
		// P-chain height. This will cause building blocks to return an error
		// until the P-chain's height has advanced.
		return time.Time{}, false, nil
	}

	return nextStartTime, true, nil
}

func (vm *VM) getPreDurangoSlotTime(
	ctx context.Context,
	blkHeight,
	pChainHeight uint64,
	parentTimestamp time.Time,
) (time.Time, error) {
	delay, err := vm.Windower.Delay(ctx, blkHeight, pChainHeight, vm.ctx.NodeID, proposer.MaxBuildWindows)
	if err != nil {
		return time.Time{}, err
	}

	// Note: The P-chain does not currently try to target any block time. It
	// notifies the consensus engine as soon as a new block may be built. To
	// avoid fast runs of blocks there is an additional minimum delay that
	// validators can specify. This delay may be an issue for high performance,
	// custom VMs. Until the P-chain is modified to target a specific block
	// time, ProposerMinBlockDelay can be configured in the net config.
	delay = max(delay, vm.MinBlkDelay)
	return parentTimestamp.Add(delay), nil
}

func (vm *VM) getPostDurangoSlotTime(
	ctx context.Context,
	blkHeight,
	pChainHeight,
	slot uint64,
	parentTimestamp time.Time,
) (time.Time, error) {
	delay, err := vm.Windower.MinDelayForProposer(
		ctx,
		blkHeight,
		pChainHeight,
		vm.ctx.NodeID,
		slot,
	)
	// Note: The P-chain does not currently try to target any block time. It
	// notifies the consensus engine as soon as a new block may be built. To
	// avoid fast runs of blocks there is an additional minimum delay that
	// validators can specify. This delay may be an issue for high performance,
	// custom VMs. Until the P-chain is modified to target a specific block
	// time, ProposerMinBlockDelay can be configured in the net config.
	switch {
	case err == nil:
		delay = max(delay, vm.MinBlkDelay)
		return parentTimestamp.Add(delay), nil
	case errors.Is(err, proposer.ErrAnyoneCanPropose):
		return parentTimestamp.Add(vm.MinBlkDelay), nil
	default:
		return time.Time{}, err
	}
}

func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	lastAccepted, err := vm.State.GetLastAccepted()
	if err == database.ErrNotFound {
		return vm.ChainVM.LastAccepted(ctx)
	}
	return lastAccepted, err
}

// CreateHandlers returns HTTP handlers for both the proposervm API and the inner ChainVM
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	// Create the proposervm-specific handler
	proposerHandler, err := NewHTTPHandler(vm)
	if err != nil {
		return nil, err
	}

	// Get the inner ChainVM handlers
	handlers, err := vms.DelegateHandlers(ctx, vm.ChainVM)
	if err != nil {
		return nil, err
	}

	// Initialize handlers map if it's nil
	if handlers == nil {
		handlers = make(map[string]http.Handler)
	}

	// Add the proposervm handler to the map
	handlers["/proposervm"] = proposerHandler
	return handlers, nil
}

func (vm *VM) repairAcceptedChainByHeight(ctx context.Context) error {
	innerLastAcceptedID, err := vm.ChainVM.LastAccepted(ctx)
	if err != nil {
		return fmt.Errorf("failed to get inner last accepted: %w", err)
	}
	innerLastAccepted, err := vm.ChainVM.GetBlock(ctx, innerLastAcceptedID)
	if err != nil {
		return fmt.Errorf("failed to get inner last accepted block: %w", err)
	}
	proLastAcceptedID, err := vm.State.GetLastAccepted()
	if err == database.ErrNotFound {
		// If the last accepted block isn't indexed yet, then the underlying
		// chain is the only chain and there is nothing to repair.
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get last accepted: %w", err)
	}
	proLastAccepted, err := vm.getPostForkBlock(ctx, proLastAcceptedID)
	if err != nil {
		return fmt.Errorf("failed to get last accepted block: %w", err)
	}

	proLastAcceptedHeight := proLastAccepted.Height()
	innerLastAcceptedHeight := innerLastAccepted.Height()
	if proLastAcceptedHeight < innerLastAcceptedHeight {
		return fmt.Errorf("proposervm height index (%d) should never be lower than the inner height index (%d)", proLastAcceptedHeight, innerLastAcceptedHeight)
	}
	if proLastAcceptedHeight == innerLastAcceptedHeight {
		// There is nothing to repair - as the heights match
		return nil
	}

	vm.logger.Info("repairing accepted chain by height",
		log.Uint64("outerHeight", proLastAcceptedHeight),
		log.Uint64("innerHeight", innerLastAcceptedHeight),
	)

	// The inner vm must be behind the proposer vm, so we must roll the
	// proposervm back.
	forkHeight, err := vm.State.GetForkHeight()
	if err != nil {
		return fmt.Errorf("failed to get fork height: %w", err)
	}

	if forkHeight > innerLastAcceptedHeight {
		// We are rolling back past the fork, so we should just forget about all
		// of our proposervm indices.
		if err := vm.State.DeleteLastAccepted(); err != nil {
			return fmt.Errorf("failed to delete last accepted: %w", err)
		}
		return vm.db.Commit()
	}

	newProLastAcceptedID, err := vm.State.GetBlockIDAtHeight(innerLastAcceptedHeight)
	if err != nil {
		// This fatal error can happen if NumHistoricalBlocks is set too
		// aggressively and the inner vm rolled back before the oldest
		// proposervm block.
		return fmt.Errorf("proposervm failed to rollback last accepted block to height (%d): %w", innerLastAcceptedHeight, err)
	}

	if err := vm.State.SetLastAccepted(newProLastAcceptedID); err != nil {
		return fmt.Errorf("failed to set last accepted: %w", err)
	}

	if err := vm.db.Commit(); err != nil {
		return fmt.Errorf("failed to commit db: %w", err)
	}

	return nil
}

func (vm *VM) setLastAcceptedMetadata(ctx context.Context) error {
	lastAcceptedID, err := vm.LastAccepted(ctx)
	if err == database.ErrNotFound {
		// If the last accepted block wasn't a PostFork block, then we don't
		// initialize the metadata.
		vm.lastAcceptedHeight = 0
		vm.lastAcceptedTime = time.Time{}
		return nil
	}
	if err != nil {
		return err
	}

	lastAccepted, err := vm.getPostForkBlock(ctx, lastAcceptedID)
	if err == database.ErrNotFound {
		// The last accepted block exists but is not a post-fork block
		// (e.g., it's the genesis block or a pre-fork block)
		// We treat this the same as if LastAccepted returned ErrNotFound
		vm.lastAcceptedHeight = 0
		vm.lastAcceptedTime = time.Time{}
		return nil
	}
	if err != nil {
		return err
	}

	// Set the last accepted height
	vm.lastAcceptedHeight = lastAccepted.Height()

	if _, ok := lastAccepted.getStatelessBlk().(statelessblock.SignedBlock); ok {
		// If the last accepted block wasn't a PostForkOption, then we don't
		// initialize the time.
		return nil
	}

	acceptedParent, err := vm.getPostForkBlock(ctx, lastAccepted.Parent())
	if err != nil {
		return err
	}
	vm.lastAcceptedTime = acceptedParent.Timestamp()
	return nil
}

func (vm *VM) parsePostForkBlock(ctx context.Context, b []byte, verifySignature bool) (PostForkBlock, error) {
	var (
		statelessBlock statelessblock.Block
		err            error
	)

	if verifySignature {
		statelessBlock, err = statelessblock.Parse(b, vm.ctx.ChainID)
	} else {
		statelessBlock, err = statelessblock.ParseWithoutVerification(b)
	}
	if err != nil {
		return nil, err
	}

	blkID := statelessBlock.ID()
	innerBlkBytes := statelessBlock.Block()
	innerBlk, err := vm.parseInnerBlock(ctx, blkID, innerBlkBytes)
	if err != nil {
		return nil, err
	}

	if statelessSignedBlock, ok := statelessBlock.(statelessblock.SignedBlock); ok {
		return &postForkBlock{
			SignedBlock: statelessSignedBlock,
			postForkCommonComponents: postForkCommonComponents{
				vm:       vm,
				innerBlk: innerBlk,
			},
		}, nil
	}

	return &postForkOption{
		Block: statelessBlock,
		postForkCommonComponents: postForkCommonComponents{
			vm:       vm,
			innerBlk: innerBlk,
		},
	}, nil
}

func (vm *VM) parsePreForkBlock(ctx context.Context, b []byte) (*preForkBlock, error) {
	blk, err := vm.ChainVM.ParseBlock(ctx, b)
	if err != nil {
		return nil, err
	}
	return &preForkBlock{
		Block: &reverseBlockAdapter{Block: blk},
		vm:    vm,
	}, nil
}

func (vm *VM) getBlock(ctx context.Context, id ids.ID) (Block, error) {
	if blk, err := vm.getPostForkBlock(ctx, id); err == nil {
		return blk, nil
	}
	return vm.getPreForkBlock(ctx, id)
}

func (vm *VM) getPostForkBlock(ctx context.Context, blkID ids.ID) (PostForkBlock, error) {
	block, exists := vm.verifiedBlocks[blkID]
	if exists {
		return block, nil
	}

	statelessBlock, err := vm.State.GetBlock(blkID)
	if err != nil {
		return nil, err
	}

	innerBlkBytes := statelessBlock.Block()
	innerBlk, err := vm.parseInnerBlock(ctx, blkID, innerBlkBytes)
	if err != nil {
		return nil, err
	}

	if statelessSignedBlock, ok := statelessBlock.(statelessblock.SignedBlock); ok {
		return &postForkBlock{
			SignedBlock: statelessSignedBlock,
			postForkCommonComponents: postForkCommonComponents{
				vm:       vm,
				innerBlk: innerBlk,
			},
		}, nil
	}
	return &postForkOption{
		Block: statelessBlock,
		postForkCommonComponents: postForkCommonComponents{
			vm:       vm,
			innerBlk: innerBlk,
		},
	}, nil
}

func (vm *VM) getPreForkBlock(ctx context.Context, blkID ids.ID) (*preForkBlock, error) {
	engineBlk, err := vm.ChainVM.GetBlock(ctx, blkID)
	if err != nil {
		return nil, err
	}
	return &preForkBlock{
		Block: &reverseBlockAdapter{Block: engineBlk},
		vm:    vm,
	}, nil
}

func (vm *VM) acceptPostForkBlock(blk PostForkBlock) error {
	height := blk.Height()
	blkID := blk.ID()

	vm.lastAcceptedHeight = height
	delete(vm.verifiedBlocks, blkID)

	// Persist this block, its height index, and its status
	if err := vm.State.SetLastAccepted(blkID); err != nil {
		return err
	}
	if err := vm.State.PutBlock(blk.getStatelessBlk()); err != nil {
		return err
	}
	if err := vm.updateHeightIndex(height, blkID); err != nil {
		return err
	}
	return vm.db.Commit()
}

func (vm *VM) verifyAndRecordInnerBlk(ctx context.Context, blockCtx *chainblock.Context, postFork PostForkBlock) error {
	innerBlk := postFork.getInnerBlk()
	postForkID := postFork.ID()
	originalInnerBlock, previouslyVerified := vm.Tree.Get(innerBlk)
	if previouslyVerified {
		innerBlk = originalInnerBlock
		// We must update all of the mappings from postFork -> innerBlock to
		// now point to originalInnerBlock.
		postFork.setInnerBlk(originalInnerBlock)
		vm.innerBlkCache.Put(postForkID, originalInnerBlock)
	}

	var (
		shouldVerifyWithCtx = blockCtx != nil
		blkWithCtx          chainblock.WithVerifyContext
		err                 error
	)
	if shouldVerifyWithCtx {
		blkWithCtx, shouldVerifyWithCtx = innerBlk.(chainblock.WithVerifyContext)
		if shouldVerifyWithCtx {
			shouldVerifyWithCtx, err = blkWithCtx.ShouldVerifyWithContext(ctx)
			if err != nil {
				return err
			}
		}
	}

	// Invariant: If either [Verify] or [VerifyWithContext] returns nil, this
	//            function must return nil. This maintains the inner block's
	//            invariant that successful verification will eventually result
	//            in accepted or rejected being called.
	if shouldVerifyWithCtx {
		// This block needs to know the P-Chain height during verification.
		// Note that [VerifyWithContext] with context may be called multiple
		// times with multiple contexts.
		err = blkWithCtx.VerifyWithContext(ctx, blockCtx)
	} else if !previouslyVerified {
		// This isn't a [chainblock.WithVerifyContext] so we only call [Verify] once.
		err = innerBlk.Verify(ctx)
	}
	if err != nil {
		return err
	}

	// Since verification passed, we should ensure the inner block tree is
	// populated.
	if !previouslyVerified {
		vm.Tree.Add(innerBlk)
	}
	vm.verifiedBlocks[postForkID] = postFork
	return nil
}

func (vm *VM) selectChildPChainHeight(ctx context.Context, minPChainHeight uint64) (uint64, error) {
	// Use GetCurrentHeight to get the recommended P-Chain height
	recommendedHeight, err := vm.validatorState.GetCurrentHeight(ctx)
	if err != nil {
		return 0, err
	}
	return max(recommendedHeight, minPChainHeight), nil
}

// parseInnerBlock attempts to parse the provided bytes as an inner block. If
// the inner block happens to be cached, then the inner block will not be
// parsed.
func (vm *VM) parseInnerBlock(ctx context.Context, outerBlkID ids.ID, innerBlkBytes []byte) (chainblock.Block, error) {
	if innerBlk, ok := vm.innerBlkCache.Get(outerBlkID); ok {
		return innerBlk, nil
	}

	engineBlk, err := vm.ChainVM.ParseBlock(ctx, innerBlkBytes)
	if err != nil {
		return nil, err
	}
	innerBlk := &reverseBlockAdapter{Block: engineBlk}
	vm.cacheInnerBlock(outerBlkID, innerBlk)
	return innerBlk, nil
}

// Caches proposervm block ID --> inner block if the inner block's height
// is within [innerBlkCacheSize] of the last accepted block's height.
func (vm *VM) cacheInnerBlock(outerBlkID ids.ID, innerBlk chainblock.Block) {
	diff := math.AbsDiff(innerBlk.Height(), vm.lastAcceptedHeight)
	if diff < innerBlkCacheSize {
		vm.innerBlkCache.Put(outerBlkID, innerBlk)
	}
}

// validatorStateWrapper wraps consensuscontext.ValidatorState to match validators.State
type validatorStateWrapper struct {
	ctx         context.Context
	vs          consensuscontext.ValidatorState
	netIDsCache cache.Cacher[ids.ID, ids.ID] // chainID -> netID cache
}

func (v *validatorStateWrapper) GetCurrentHeight(ctx context.Context) (uint64, error) {
	return v.vs.GetCurrentHeight(ctx)
}

func (v *validatorStateWrapper) GetValidatorSet(ctx context.Context, height uint64, netID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	// Get the validator set from the consensus version which returns map[ids.NodeID]uint64
	valSet, err := v.vs.GetValidatorSet(height, netID)
	if err != nil {
		return nil, err
	}

	// Convert map[ids.NodeID]uint64 to map[ids.NodeID]*validators.GetValidatorOutput
	result := make(map[ids.NodeID]*validators.GetValidatorOutput, len(valSet))
	for nodeID, weight := range valSet {
		result[nodeID] = &validators.GetValidatorOutput{
			NodeID: nodeID,
			Weight: weight,
		}
	}
	return result, nil
}

func (v *validatorStateWrapper) GetMinimumHeight(ctx context.Context) (uint64, error) {
	return v.vs.GetMinimumHeight(ctx)
}

func (v *validatorStateWrapper) GetNetworkID(ctx context.Context, chainID ids.ID) (ids.ID, error) {
	// Check cache first
	if netID, ok := v.netIDsCache.Get(chainID); ok {
		return netID, nil
	}

	// Cache miss - fetch from underlying validator state
	netID, err := v.vs.GetNetworkID(chainID)
	if err != nil {
		return ids.Empty, err
	}

	// Cache the result
	v.netIDsCache.Put(chainID, netID)
	return netID, nil
}

func (v *validatorStateWrapper) GetCurrentValidators(ctx context.Context, height uint64, netID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	// For now, return empty set - need proper implementation
	return make(map[ids.NodeID]*validators.GetValidatorOutput), nil
}

func (v *validatorStateWrapper) GetCurrentValidatorSet(ctx context.Context, netID ids.ID) (map[ids.ID]*validators.GetValidatorOutput, uint64, error) {
	// For now, return empty set with current height - need proper implementation
	height, err := v.vs.GetCurrentHeight(ctx)
	if err != nil {
		return nil, 0, err
	}
	return make(map[ids.ID]*validators.GetValidatorOutput), height, nil
}

// interfacesToConsensusValidatorStateAdapter adapts ValidatorState from chainCtx
type interfacesToConsensusValidatorStateAdapter struct {
	ctx         context.Context
	vs          consensuscontext.ValidatorState
	netIDsCache cache.Cacher[ids.ID, ids.ID] // chainID -> netID cache
}

func (a *interfacesToConsensusValidatorStateAdapter) GetMinimumHeight(ctx context.Context) (uint64, error) {
	return a.vs.GetMinimumHeight(ctx)
}

func (a *interfacesToConsensusValidatorStateAdapter) GetCurrentHeight(ctx context.Context) (uint64, error) {
	return a.vs.GetCurrentHeight(ctx)
}

func (a *interfacesToConsensusValidatorStateAdapter) GetChainID(chainID ids.ID) (ids.ID, error) {
	return a.vs.GetChainID(chainID)
}

func (a *interfacesToConsensusValidatorStateAdapter) GetNetworkID(chainID ids.ID) (ids.ID, error) {
	// Check cache first
	if netID, ok := a.netIDsCache.Get(chainID); ok {
		return netID, nil
	}

	// Cache miss - fetch from underlying validator state
	netID, err := a.vs.GetNetworkID(chainID)
	if err != nil {
		return ids.Empty, err
	}

	// Cache the result
	a.netIDsCache.Put(chainID, netID)
	return netID, nil
}

func (a *interfacesToConsensusValidatorStateAdapter) GetValidatorSet(height uint64, netID ids.ID) (map[ids.NodeID]uint64, error) {
	// Get the validator set from the interfaces version which takes context
	valSet, err := a.vs.GetValidatorSet(height, netID)
	if err != nil {
		return nil, err
	}

	// Already in the right format - map[ids.NodeID]uint64
	return valSet, nil
}

func (a *interfacesToConsensusValidatorStateAdapter) GetCurrentValidators(ctx context.Context, height uint64, netID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	// Get the validator set from the interfaces version
	valSet, err := a.vs.GetValidatorSet(height, netID)
	if err != nil {
		return nil, err
	}

	// Convert map[ids.NodeID]uint64 to map[ids.NodeID]*GetValidatorOutput
	result := make(map[ids.NodeID]*validators.GetValidatorOutput, len(valSet))
	for nodeID, weight := range valSet {
		result[nodeID] = &validators.GetValidatorOutput{
			NodeID:    nodeID,
			Weight:    weight,
			PublicKey: nil, // Public key not available in this interface
		}
	}
	return result, nil
}
