// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import (
	"context"
	"errors"

	"github.com/luxfi/runtime"
)

var (
	_ Block             = (*BlockWrapper)(nil)
	_ WithVerifyRuntime = (*BlockWrapper)(nil)

	errExpectedBlockWithVerifyRuntime = errors.New("expected block.WithVerifyRuntime")
)

// BlockWrapper wraps a linear Block while adding a smart caching layer to improve
// VM performance.
type BlockWrapper struct {
	Block

	state *State
}

// Verify verifies the underlying block, evicts from the unverified block cache
// and if the block passes verification, adds it to [cache.verifiedBlocks].
// Note: it is guaranteed that if a block passes verification it will be added to
// consensus and eventually be decided ie. either Accept/Reject will be called
// on [bw] removing it from [verifiedBlocks].
func (bw *BlockWrapper) Verify(ctx context.Context) error {
	if err := bw.Block.Verify(ctx); err != nil {
		// Note: we cannot cache blocks failing verification in case
		// the error is temporary and the block could become valid in
		// the future.
		return err
	}

	blkID := bw.ID()
	bw.state.unverifiedBlocks.Evict(blkID)
	bw.state.verifiedBlocks[blkID] = bw
	return nil
}

// VerifyWithRuntime verifies the underlying block with runtime
func (bw *BlockWrapper) VerifyWithRuntime(ctx context.Context, rt *runtime.Runtime) error {
	// If the embedded block supports context verification, use it
	if withCtx, ok := bw.Block.(WithVerifyRuntime); ok {
		shouldVerify, err := withCtx.ShouldVerifyWithRuntime(ctx)
		if err != nil {
			return err
		}
		if shouldVerify {
			return withCtx.VerifyWithRuntime(ctx, rt)
		}
	}
	// Otherwise fall back to regular Verify
	return bw.Verify(ctx)
}

// ShouldVerifyWithRuntime checks if the underlying block should be verified
// with a block context. If the underlying block does not implement the
// block.WithVerifyRuntime interface, returns false without an error. Does not
// touch any block cache.
func (bw *BlockWrapper) ShouldVerifyWithRuntime(ctx context.Context) (bool, error) {
	blkWithCtx, ok := bw.Block.(WithVerifyRuntime)
	if !ok {
		return false, nil
	}
	return blkWithCtx.ShouldVerifyWithRuntime(ctx)
}

// Accept accepts the underlying block, removes it from verifiedBlocks, caches it as a decided
// block, and updates the last accepted block.
func (bw *BlockWrapper) Accept(ctx context.Context) error {
	blkID := bw.ID()
	delete(bw.state.verifiedBlocks, blkID)
	bw.state.decidedBlocks.Put(blkID, bw)
	bw.state.lastAcceptedBlock = bw

	return bw.Block.Accept(ctx)
}

// Reject rejects the underlying block, removes it from processing blocks, and caches it as a
// decided block.
func (bw *BlockWrapper) Reject(ctx context.Context) error {
	blkID := bw.ID()
	delete(bw.state.verifiedBlocks, blkID)
	bw.state.decidedBlocks.Put(blkID, bw)
	return bw.Block.Reject(ctx)
}

// OracleBlock is a block that can have multiple valid children, and one needs
// to be chosen by an oracle.
type OracleBlock interface {
	Block

	// Options returns the block options that may be chosen by the oracle.
	Options(context.Context) ([2]Block, error)
}
