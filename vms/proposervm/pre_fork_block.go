// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package proposervm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/log"

	chainblock "github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/vms/proposervm/block"
	"github.com/luxfi/vm/vms/proposervm/lp181"
)

var (
	_ Block = (*preForkBlock)(nil)

	errChildOfPreForkBlockHasProposer = errors.New("child of pre-fork block has proposer")
)

type preForkBlock struct {
	chainblock.Block
	vm *VM
}

// EpochBit returns the epoch bit for FPC
func (b *preForkBlock) EpochBit() bool {
	// Forward to inner block if it supports it
	if innerBlk, ok := b.Block.(interface{ EpochBit() bool }); ok {
		return innerBlk.EpochBit()
	}
	return false
}

// FPCVotes returns embedded fast-path vote references
func (b *preForkBlock) FPCVotes() [][]byte {
	// Forward to inner block if it supports it
	if innerBlk, ok := b.Block.(interface{ FPCVotes() [][]byte }); ok {
		return innerBlk.FPCVotes()
	}
	return nil
}

// Timestamp returns the timestamp of the inner block
func (b *preForkBlock) Timestamp() time.Time {
	// Forward to inner block if it supports it
	if innerBlk, ok := b.Block.(interface{ Timestamp() time.Time }); ok {
		return innerBlk.Timestamp()
	}
	// Fallback to current time
	return b.vm.Time()
}

func (b *preForkBlock) Accept(ctx context.Context) error {
	if err := b.acceptOuterBlk(); err != nil {
		return err
	}
	return b.acceptInnerBlk(ctx)
}

func (*preForkBlock) acceptOuterBlk() error {
	return nil
}

func (b *preForkBlock) acceptInnerBlk(ctx context.Context) error {
	return b.Block.Accept(ctx)
}

func (b *preForkBlock) Verify(ctx context.Context) error {
	parent, err := b.vm.getPreForkBlock(ctx, b.Block.Parent())
	if err != nil {
		return err
	}
	return parent.verifyPreForkChild(ctx, b)
}

func (b *preForkBlock) Options(ctx context.Context) ([2]chainblock.Block, error) {
	oracleBlk, ok := b.Block.(OracleBlock)
	if !ok {
		return [2]chainblock.Block{}, errNotOracle
	}

	options, err := oracleBlk.Options(ctx)
	if err != nil {
		return [2]chainblock.Block{}, err
	}
	// A pre-fork block's child options are always pre-fork blocks
	return [2]chainblock.Block{
		&preForkBlock{
			Block: options[0],
			vm:    b.vm,
		},
		&preForkBlock{
			Block: options[1],
			vm:    b.vm,
		},
	}, nil
}

func (b *preForkBlock) getInnerBlk() chainblock.Block {
	return b.Block
}

func (b *preForkBlock) verifyPreForkChild(ctx context.Context, child *preForkBlock) error {
	// FIX 2: Byzantine validation BEFORE proposer window check
	// Ensure parent is an oracle block if post-fork
	parentTimestamp := b.Timestamp()
	if b.vm.Upgrades.IsApricotPhase4Activated(parentTimestamp) {
		if err := verifyIsOracleBlock(ctx, b.Block); err != nil {
			// If parent is post-fork but not an oracle block,
			// preFork children are not allowed
			return errUnexpectedBlockType
		}

		b.vm.logger.Debug("allowing pre-fork block after the fork time",
			log.String("reason", "parent is an oracle block"),
			log.Stringer("blkID", b.ID()),
		)
	}

	return child.Block.Verify(ctx)
}

// This method only returns nil once (during the transition)
func (b *preForkBlock) verifyPostForkChild(ctx context.Context, child *postForkBlock) error {
	// FIX 4: Oracle parent validation - check if parent is oracle
	parentIsOracle := verifyIsOracleBlock(ctx, b.Block) == nil
	if parentIsOracle && child.SignedBlock.Proposer() != ids.EmptyNodeID {
		return errChildOfPreForkBlockHasProposer
	}

	if err := verifyIsNotOracleBlock(ctx, b.Block); err != nil {
		return err
	}

	childID := child.ID()
	childPChainHeight := child.PChainHeight()
	currentPChainHeight, err := b.vm.validatorState.GetCurrentHeight(ctx)
	if err != nil {
		b.vm.logger.Error("block verification failed",
			log.String("reason", "failed to get current P-Chain height"),
			log.Stringer("blkID", childID),
			log.Err(err),
		)
		return err
	}
	if childPChainHeight > currentPChainHeight {
		return fmt.Errorf("%w: %d > %d",
			errPChainHeightNotReached,
			childPChainHeight,
			currentPChainHeight,
		)
	}
	if childPChainHeight < b.vm.Upgrades.ApricotPhase4MinPChainHeight {
		return errPChainHeightTooLow
	}

	// Make sure [b] is the parent of [child]'s inner block
	expectedInnerParentID := b.ID()
	innerParentID := child.innerBlk.Parent()
	if innerParentID != expectedInnerParentID {
		return errInnerParentMismatch
	}

	// A *preForkBlock can only have a *postForkBlock child
	// if the *preForkBlock is the last *preForkBlock before activation takes effect
	// (its timestamp is at or after the activation time)
	parentTimestamp := b.Timestamp()
	if !b.vm.Upgrades.IsApricotPhase4Activated(parentTimestamp) {
		return errProposersNotActivated
	}

	// Child's timestamp must be at or after its parent's timestamp
	childTimestamp := child.Timestamp()
	if childTimestamp.Before(parentTimestamp) {
		return errTimeNotMonotonic
	}

	// Validate epoch for Granite upgrade (LP-181)
	// Pre-fork blocks always have empty epoch, so use that as parent epoch
	parentEpoch := block.Epoch{} // Pre-fork blocks have no epoch
	childEpoch := child.PChainEpoch()
	// For pre-fork blocks, we don't have explicit P-chain height tracking.
	// We use 0 as the parent P-chain height for genesis/pre-fork blocks.
	parentPChainHeight := uint64(0)
	expectedEpoch := lp181.NewEpoch(b.vm.Upgrades, parentPChainHeight, parentEpoch, parentTimestamp, childTimestamp)
	if childEpoch != expectedEpoch {
		return fmt.Errorf("%w: epoch %v != expected %v", errEpochMismatch, childEpoch, expectedEpoch)
	}

	// Child timestamp can't be too far in the future
	maxTimestamp := b.vm.Time().Add(maxSkew)
	if childTimestamp.After(maxTimestamp) {
		return errTimeTooAdvanced
	}

	// Verify the lack of signature on the node
	if child.SignedBlock.Proposer() != ids.EmptyNodeID {
		return errChildOfPreForkBlockHasProposer
	}

	// Verify the inner block and track it as verified
	return b.vm.verifyAndRecordInnerBlk(ctx, nil, child)
}

func (*preForkBlock) verifyPostForkOption(context.Context, *postForkOption) error {
	return errUnexpectedBlockType
}

func (b *preForkBlock) buildChild(ctx context.Context) (Block, error) {
	parentTimestamp := b.Timestamp()
	if !b.vm.Upgrades.IsApricotPhase4Activated(parentTimestamp) {
		// The chain hasn't forked yet
		// FIX 5: BuildBlockWithContext - proper context passing
		var innerBlock chainblock.Block
		if b.vm.blockBuilderVM != nil {
			builtBlock, err := b.vm.blockBuilderVM.BuildBlockWithContext(ctx, &chainblock.Context{})
			if err != nil {
				return nil, err
			}
			innerBlock = builtBlock
		} else {
			engineBlock, err := b.vm.ChainVM.BuildBlock(ctx)
			if err != nil {
				return nil, err
			}
			innerBlock = &reverseBlockAdapter{Block: engineBlock}
		}

		b.vm.logger.Info("built block",
			log.Stringer("blkID", innerBlock.ID()),
			log.Uint64("height", innerBlock.Height()),
			log.Time("parentTimestamp", parentTimestamp),
		)

		return &preForkBlock{
			Block: innerBlock,
			vm:    b.vm,
		}, nil
	}

	// The chain is currently forking

	parentID := b.ID()
	newTimestamp := b.vm.Time().Truncate(time.Second)
	if newTimestamp.Before(parentTimestamp) {
		newTimestamp = parentTimestamp
	}

	// The child's P-Chain height is proposed as the optimal P-Chain height that
	// is at least the minimum height
	pChainHeight, err := b.vm.selectChildPChainHeight(ctx, b.vm.Upgrades.ApricotPhase4MinPChainHeight)
	if err != nil {
		b.vm.logger.Error("unexpected build block failure",
			log.String("reason", "failed to calculate optimal P-chain height"),
			log.Stringer("parentID", parentID),
			log.Err(err),
		)
		return nil, err
	}

	var innerBlock chainblock.Block
	if b.vm.blockBuilderVM != nil {
		// VM supports BuildBlockWithContext
		builtBlock, err := b.vm.blockBuilderVM.BuildBlockWithContext(ctx, &chainblock.Context{})
		if err != nil {
			return nil, err
		}
		innerBlock = builtBlock
	} else {
		// VM doesn't support BuildBlockWithContext, use BuildBlock
		engineBlock, err := b.vm.ChainVM.BuildBlock(ctx)
		if err != nil {
			return nil, err
		}
		innerBlock = &reverseBlockAdapter{Block: engineBlock}
	}

	// Calculate the epoch for the child block based on Granite activation
	parentEpoch := block.Epoch{} // Pre-fork blocks have no epoch
	// For pre-fork blocks, we don't have explicit P-chain height tracking.
	// We use 0 as the parent P-chain height for genesis/pre-fork blocks.
	parentPChainHeight := uint64(0)
	childEpoch := lp181.NewEpoch(b.vm.Upgrades, parentPChainHeight, parentEpoch, parentTimestamp, newTimestamp)

	statelessBlock, err := block.BuildUnsigned(
		parentID,
		newTimestamp,
		pChainHeight,
		childEpoch,
		innerBlock.Bytes(),
	)
	if err != nil {
		return nil, err
	}

	blk := &postForkBlock{
		SignedBlock: statelessBlock,
		postForkCommonComponents: postForkCommonComponents{
			vm:       b.vm,
			innerBlk: innerBlock,
		},
	}

	b.vm.logger.Info("built block",
		log.Stringer("blkID", blk.ID()),
		log.Stringer("innerBlkID", innerBlock.ID()),
		log.Uint64("height", blk.Height()),
		log.Uint64("pChainHeight", pChainHeight),
		log.Time("parentTimestamp", parentTimestamp),
		log.Time("blockTimestamp", newTimestamp))
	return blk, nil
}

func (*preForkBlock) pChainHeight(context.Context) (uint64, error) {
	return 0, nil
}

func (*preForkBlock) pChainEpoch(context.Context) (chainblock.Epoch, error) {
	return chainblock.Epoch{}, nil
}

func (b *preForkBlock) selectChildPChainHeight(ctx context.Context) (uint64, error) {
	return b.vm.selectChildPChainHeight(ctx, 0)
}
