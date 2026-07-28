// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import (
	"context"
	"errors"

	"github.com/luxfi/runtime"
	vmchain "github.com/luxfi/vm/chain"
)

var (
	_ vmchain.Block             = (*BlockWrapper)(nil)
	_ vmchain.WithVerifyRuntime = (*BlockWrapper)(nil)

	errExpectedBlockWithVerifyRuntime = errors.New("expected vmchain.WithVerifyRuntime")
)

// BlockWrapper wraps a linear Block while adding a smart caching layer to improve
// VM performance.
type BlockWrapper struct {
	vmchain.Block

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
	// verifiedBlocks is a plain map shared with every concurrent ZAP RPC handler; State
	// owns its lock. Taken AFTER Block.Verify so it is never held across the inner VM.
	bw.state.blocksLock.Lock()
	bw.state.verifiedBlocks[blkID] = bw
	bw.state.blocksLock.Unlock()
	return nil
}

// VerifyWithRuntime verifies the underlying block with runtime
func (bw *BlockWrapper) VerifyWithRuntime(ctx context.Context, rt *runtime.Runtime) error {
	// If the embedded block supports context verification, use it
	if withCtx, ok := bw.Block.(vmchain.WithVerifyRuntime); ok {
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
// vmchain.WithVerifyRuntime interface, returns false without an error. Does not
// touch any block cache.
func (bw *BlockWrapper) ShouldVerifyWithRuntime(ctx context.Context) (bool, error) {
	blkWithCtx, ok := bw.Block.(vmchain.WithVerifyRuntime)
	if !ok {
		return false, nil
	}
	return blkWithCtx.ShouldVerifyWithRuntime(ctx)
}

// VerifyWithRuntime verifies the underlying block with the given runtime,
// evicts from the unverified block cache and if the block passes verification,
// adds it to [cache.verifiedBlocks].
// Note: it is guaranteed that if a block passes verification it will be added
// to consensus and eventually be decided ie. either Accept/Reject will be
// called on [bw] removing it from [verifiedBlocks].
//
// Note: If the underlying block does not implement the consensuschain.WithVerifyRuntime
// interface, an error is always returned because ShouldVerifyWithRuntime will
// always return false in this case and VerifyWithRuntime should never be
// called.

// Accept accepts the underlying block, removes it from verifiedBlocks, caches it as a decided
// block, and updates the last accepted block.
func (bw *BlockWrapper) Accept(ctx context.Context) error {
	blkID := bw.ID()
	bw.state.blocksLock.Lock()
	delete(bw.state.verifiedBlocks, blkID)
	bw.state.lastAcceptedBlock = bw
	bw.state.blocksLock.Unlock()
	bw.state.decidedBlocks.Put(blkID, bw)

	return bw.Block.Accept(ctx)
}

// Reject rejects the underlying block, removes it from processing blocks, and caches it as a
// decided block.
func (bw *BlockWrapper) Reject(ctx context.Context) error {
	blkID := bw.ID()
	bw.state.blocksLock.Lock()
	delete(bw.state.verifiedBlocks, blkID)
	bw.state.blocksLock.Unlock()
	bw.state.decidedBlocks.Put(blkID, bw)
	return bw.Block.Reject(ctx)
}

// OracleBlock is a block that can have multiple valid children, and one needs
// to be chosen by an oracle.
type OracleBlock interface {
	vmchain.Block

	// Options returns the block options that may be chosen by the oracle.
	Options(context.Context) ([2]vmchain.Block, error)
}
