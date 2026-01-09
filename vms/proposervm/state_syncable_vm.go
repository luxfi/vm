// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package proposervm

import (
	"context"
	"fmt"

	"github.com/luxfi/log"

	chainblock "github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/database"
	"github.com/luxfi/vm/vms/proposervm/summary"
)

func (vm *VM) StateSyncEnabled(ctx context.Context) (bool, error) {
	if vm.ssVM == nil {
		return false, nil
	}

	return vm.ssVM.StateSyncEnabled(ctx)
}

func (vm *VM) GetOngoingSyncStateSummary(ctx context.Context) (chainblock.StateSummary, error) {
	if vm.ssVM == nil {
		return nil, chainblock.ErrStateSyncableVMNotImplemented
	}

	innerSummary, err := vm.ssVM.GetOngoingSyncStateSummary(ctx)
	if err != nil {
		return nil, err // includes database.ErrNotFound case
	}

	return vm.buildStateSummary(ctx, innerSummary)
}

func (vm *VM) GetLastStateSummary(ctx context.Context) (chainblock.StateSummary, error) {
	if vm.ssVM == nil {
		return nil, chainblock.ErrStateSyncableVMNotImplemented
	}

	// Extract inner vm's last state summary
	innerSummary, err := vm.ssVM.GetLastStateSummary(ctx)
	if err != nil {
		return nil, err // including database.ErrNotFound case
	}

	return vm.buildStateSummary(ctx, innerSummary)
}

// Note: it's important that ParseStateSummary do not use any index or state
// to allow summaries being parsed also by freshly started node with no previous state.
func (vm *VM) ParseStateSummary(ctx context.Context, summaryBytes []byte) (chainblock.StateSummary, error) {
	if vm.ssVM == nil {
		return nil, chainblock.ErrStateSyncableVMNotImplemented
	}

	statelessSummary, err := summary.Parse(summaryBytes)
	if err != nil {
		// it may be a preFork summary
		return vm.ssVM.ParseStateSummary(ctx, summaryBytes)
	}

	innerSummary, err := vm.ssVM.ParseStateSummary(ctx, statelessSummary.InnerSummaryBytes())
	if err != nil {
		return nil, fmt.Errorf("could not parse inner summary due to: %w", err)
	}
	block, err := vm.parsePostForkBlock(ctx, statelessSummary.BlockBytes(), true)
	if err != nil {
		return nil, fmt.Errorf("could not parse proposervm block bytes from summary due to: %w", err)
	}

	return &stateSummary{
		StateSummary: statelessSummary,
		innerSummary: innerSummary,
		block:        block,
		vm:           vm,
	}, nil
}

func (vm *VM) GetStateSummary(ctx context.Context, height uint64) (chainblock.StateSummary, error) {
	if vm.ssVM == nil {
		return nil, chainblock.ErrStateSyncableVMNotImplemented
	}

	innerSummary, err := vm.ssVM.GetStateSummary(ctx, height)
	if err != nil {
		return nil, err // including database.ErrNotFound case
	}

	return vm.buildStateSummary(ctx, innerSummary)
}

// Note: building state summary requires a well formed height index.
func (vm *VM) buildStateSummary(ctx context.Context, innerSummary chainblock.StateSummary) (chainblock.StateSummary, error) {
	forkHeight, err := vm.GetForkHeight()
	switch err {
	case nil:
		if innerSummary.Height() < forkHeight {
			return innerSummary, nil
		}
	case database.ErrNotFound:
		// fork has not been reached since there is not fork height
		// just return innerSummary
		vm.logger.Debug("built pre-fork summary",
			log.Stringer("summaryID", innerSummary.ID()),
			log.Uint64("summaryHeight", innerSummary.Height()),
		)
		return innerSummary, nil
	default:
		return nil, err
	}

	height := innerSummary.Height()
	blkID, err := vm.GetBlockIDAtHeight(ctx, height)
	if err != nil {
		vm.logger.Debug("failed to fetch proposervm block ID",
			log.Uint64("height", height),
			log.Err(err),
		)
		return nil, err
	}
	block, err := vm.getPostForkBlock(ctx, blkID)
	if err != nil {
		vm.logger.Warn("failed to fetch proposervm block",
			log.Stringer("blkID", blkID),
			log.Uint64("height", height),
			log.Err(err),
		)
		return nil, err
	}

	statelessSummary, err := summary.Build(forkHeight, block.Bytes(), innerSummary.Bytes())
	if err != nil {
		return nil, err
	}

	vm.logger.Debug("built post-fork summary",
		log.Stringer("summaryID", statelessSummary.ID()),
		log.Uint64("summaryHeight", forkHeight),
	)
	return &stateSummary{
		StateSummary: statelessSummary,
		innerSummary: innerSummary,
		block:        block,
		vm:           vm,
	}, nil
}
