// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import (
	"context"
	"time"

	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/ids"
	"github.com/luxfi/runtime"
	"github.com/luxfi/version"
)

// VersionInfo is an alias for version.Application for compatibility.
// Deprecated: Use *version.Application directly.
type VersionInfo = version.Application

// HealthResult is an alias for block.HealthCheckResult for compatibility.
type HealthResult = block.HealthCheckResult

// Message is an alias for block.Message for compatibility.
type Message = block.Message

// Fx is an alias for block.Fx for compatibility.
type Fx = block.Fx

// Block is an alias for consensus/engine/chain/block.Block for compatibility.
// New code should use github.com/luxfi/consensus/engine/chain/block.Block directly.
type Block = block.Block

// Epoch is an alias for block.Epoch for compatibility.
type Epoch = block.Epoch

// SignedBlock is an alias for block.SignedBlock for compatibility.
type SignedBlock = block.SignedBlock

// ChainVM is an alias for block.ChainVM for compatibility.
// This allows implementations that use interface{} types to work seamlessly.
type ChainVM = block.ChainVM

// StateSyncMode is an alias for block.StateSyncMode for compatibility.
type StateSyncMode = block.StateSyncMode

// Re-export StateSyncMode constants
const (
	StateSyncSkipped = block.StateSyncSkipped
	StateSyncStatic  = block.StateSyncStatic
	StateSyncDynamic = block.StateSyncDynamic
)

// StateSyncableVM defines a VM that supports state sync.
type StateSyncableVM interface {
	ChainVM

	// StateSyncEnabled returns whether state sync is enabled.
	StateSyncEnabled(context.Context) (bool, error)

	// GetOngoingSyncStateSummary returns the ongoing sync state summary.
	GetOngoingSyncStateSummary(context.Context) (StateSummary, error)

	// GetLastStateSummary returns the last state summary.
	GetLastStateSummary(context.Context) (StateSummary, error)

	// ParseStateSummary parses a state summary.
	ParseStateSummary(context.Context, []byte) (StateSummary, error)

	// GetStateSummary gets a state summary by height.
	GetStateSummary(context.Context, uint64) (StateSummary, error)
}

// StateSummary represents a state summary.
type StateSummary interface {
	ID() ids.ID
	Height() uint64
	Bytes() []byte
	Accept(context.Context) (StateSyncMode, error)
}

// Context is an alias for block.Context for compatibility.
// PChainHeight is the P-Chain height to use for Warp message validation.
type Context = block.Context

// BuildBlockWithRuntimeChainVM extends ChainVM with runtime support.
type BuildBlockWithRuntimeChainVM interface {
	ChainVM
	BuildBlockWithRuntime(context.Context, *runtime.Runtime) (Block, error)
}

// BuildBlockWithContextChainVM extends ChainVM with proposer context support.
type BuildBlockWithContextChainVM interface {
	ChainVM
	BuildBlockWithContext(context.Context, *Context) (Block, error)
}

// BatchedChainVM extends ChainVM with batch operations.
type BatchedChainVM interface {
	ChainVM
	GetAncestors(
		ctx context.Context,
		blkID ids.ID,
		maxBlocksNum int,
		maxBlocksSize int,
		maxBlocksRetrievalTime time.Duration,
	) ([][]byte, error)
	BatchedParseBlock(ctx context.Context, blks [][]byte) ([]Block, error)
}

// WithVerifyRuntime provides verify support with runtime.
type WithVerifyRuntime interface {
	// VerifyWithRuntime verifies with runtime.
	VerifyWithRuntime(context.Context, *runtime.Runtime) error

	// ShouldVerifyWithRuntime returns whether to verify with runtime.
	ShouldVerifyWithRuntime(context.Context) (bool, error)
}

// GetAncestors retrieves ancestors of a block up to a maximum count.
func GetAncestors(
	ctx context.Context,
	vm ChainVM,
	blkID ids.ID,
	maxBlocks int,
	maxBlocksSize int,
	maxBlocksRetrievalTime time.Duration,
) ([][]byte, error) {
	if maxBlocks <= 0 {
		return nil, nil
	}

	startTime := time.Now()
	ancestors := make([][]byte, 0, maxBlocks)
	totalSize := 0

	for len(ancestors) < maxBlocks && totalSize < maxBlocksSize {
		if time.Since(startTime) > maxBlocksRetrievalTime {
			break
		}

		blk, err := vm.GetBlock(ctx, blkID)
		if err != nil {
			break
		}

		blkBytes := blk.Bytes()
		totalSize += len(blkBytes)
		if totalSize > maxBlocksSize {
			break
		}

		ancestors = append(ancestors, blkBytes)
		blkID = blk.ParentID()
	}

	return ancestors, nil
}

// ChainVMWithNetwork is an alias for ChainVM which now includes network callbacks.
// Deprecated: Use ChainVM directly.
type ChainVMWithNetwork = ChainVM

// ChainVMWithHealth is an alias for ChainVM which now includes health check.
// Deprecated: Use ChainVM directly.
type ChainVMWithHealth = ChainVM
