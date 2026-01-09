// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package proposervm

import (
	"context"
	"time"

	chainblock "github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/vms/proposervm/block"
)

var _ PostForkBlock = (*postForkBlock)(nil)

type postForkBlock struct {
	block.SignedBlock
	postForkCommonComponents

	// slot of the proposer that produced this block.
	// It is populated in verifyPostDurangoBlockDelay.
	// It is used to report metrics during Accept.
	slot *uint64
}

// Status returns the status of the inner block
func (b *postForkBlock) Status() uint8 {
	return b.innerBlk.Status()
}

// Height returns the height of the inner block - explicit to resolve ambiguity
func (b *postForkBlock) Height() uint64 {
	return b.postForkCommonComponents.Height()
}

// Accept:
// 1) Sets this blocks status to Accepted.
// 2) Persists this block in storage
// 3) Calls Reject() on siblings of this block and their descendants.
func (b *postForkBlock) Accept(ctx context.Context) error {
	if err := b.acceptOuterBlk(); err != nil {
		return err
	}
	if err := b.acceptInnerBlk(ctx); err != nil {
		return err
	}
	if b.slot != nil {
		b.vm.acceptedBlocksSlotHistogram.Observe(float64(*b.slot))
	}
	b.updateLastAcceptedTimestampMetric(outerBlockTypeMetricLabel, b.Timestamp())
	b.updateLastAcceptedTimestampMetric(innerBlockTypeMetricLabel, b.innerBlk.Timestamp())
	return nil
}

const (
	innerBlockTypeMetricLabel = "inner"
	outerBlockTypeMetricLabel = "proposervm"
)

func (b *postForkBlock) updateLastAcceptedTimestampMetric(blockTypeLabel string, t time.Time) {
	g := b.vm.lastAcceptedTimestampGaugeVec.WithLabelValues(blockTypeLabel)
	g.Set(float64(t.Unix()))
}

func (b *postForkBlock) acceptOuterBlk() error {
	// Update in-memory references
	b.vm.lastAcceptedTime = b.Timestamp()

	return b.vm.acceptPostForkBlock(b)
}

func (b *postForkBlock) acceptInnerBlk(ctx context.Context) error {
	// mark the inner block as accepted and all conflicting inner blocks as
	// rejected
	return b.vm.Tree.Accept(ctx, b.innerBlk)
}

func (b *postForkBlock) Reject(ctx context.Context) error {
	// We do not reject the inner block here because it may be accepted later
	delete(b.vm.verifiedBlocks, b.ID())
	return nil
}

// Return this block's parent, or a *missing.Block if
// we don't have the parent.
func (b *postForkBlock) Parent() ids.ID {
	return b.ParentID()
}

// EpochBit returns the epoch bit for FPC
func (b *postForkBlock) EpochBit() bool {
	// Forward to inner block if it supports it
	if innerBlk, ok := b.innerBlk.(interface{ EpochBit() bool }); ok {
		return innerBlk.EpochBit()
	}
	return false
}

// FPCVotes returns embedded fast-path vote references
func (b *postForkBlock) FPCVotes() [][]byte {
	// Forward to inner block if it supports it
	if innerBlk, ok := b.innerBlk.(interface{ FPCVotes() [][]byte }); ok {
		return innerBlk.FPCVotes()
	}
	return nil
}

// Timestamp returns the block's timestamp from the SignedBlock
func (b *postForkBlock) Timestamp() time.Time {
	return b.SignedBlock.Timestamp()
}

// If Verify() returns nil, Accept() or Reject() will eventually be called on
// [b] and [b.innerBlk]
func (b *postForkBlock) Verify(ctx context.Context) error {
	parent, err := b.vm.getBlock(ctx, b.ParentID())
	if err != nil {
		return err
	}
	return parent.verifyPostForkChild(ctx, b)
}

// Return the two options for the block that follows [b]
func (b *postForkBlock) Options(ctx context.Context) ([2]chainblock.Block, error) {
	innerOracleBlk, ok := b.innerBlk.(OracleBlock)
	if !ok {
		// [b]'s innerBlk isn't an oracle block
		return [2]chainblock.Block{}, errNotOracle
	}

	// The inner block's child options
	innerOptions, err := innerOracleBlk.Options(ctx)
	if err != nil {
		return [2]chainblock.Block{}, err
	}

	parentID := b.ID()
	outerOptions := [2]chainblock.Block{}
	for i, innerOption := range innerOptions {
		// Wrap the inner block's child option
		statelessOuterOption, err := block.BuildOption(
			parentID,
			innerOption.Bytes(),
		)
		if err != nil {
			return [2]chainblock.Block{}, err
		}

		outerOptions[i] = &postForkOption{
			Block: statelessOuterOption,
			postForkCommonComponents: postForkCommonComponents{
				vm:       b.vm,
				innerBlk: innerOption,
			},
		}
	}
	return outerOptions, nil
}

// A post-fork block can never have a pre-fork child
func (*postForkBlock) verifyPreForkChild(context.Context, *preForkBlock) error {
	return errUnsignedChild
}

func (b *postForkBlock) verifyPostForkChild(ctx context.Context, child *postForkBlock) error {
	parentTimestamp := b.Timestamp()
	parentPChainHeight := b.PChainHeight()
	parentEpoch := toChainBlockEpoch(b.PChainEpoch())
	return b.postForkCommonComponents.Verify(
		ctx,
		parentTimestamp,
		parentPChainHeight,
		parentEpoch,
		child,
	)
}

func (b *postForkBlock) verifyPostForkOption(ctx context.Context, child *postForkOption) error {
	if err := verifyIsOracleBlock(ctx, b.innerBlk); err != nil {
		return err
	}

	// Make sure [b]'s inner block is the parent of [child]'s inner block
	expectedInnerParentID := b.innerBlk.ID()
	innerParentID := child.innerBlk.Parent()
	if innerParentID != expectedInnerParentID {
		return errInnerParentMismatch
	}

	return child.vm.verifyAndRecordInnerBlk(ctx, nil, child)
}

// Return the child (a *postForkBlock) of this block
func (b *postForkBlock) buildChild(ctx context.Context) (Block, error) {
	return b.postForkCommonComponents.buildChild(
		ctx,
		b.ID(),
		b.Timestamp(),
		b.PChainHeight(),
		toChainBlockEpoch(b.PChainEpoch()),
	)
}

func (b *postForkBlock) pChainHeight(context.Context) (uint64, error) {
	return b.PChainHeight(), nil
}

func (b *postForkBlock) pChainEpoch(context.Context) (chainblock.Epoch, error) {
	return toChainBlockEpoch(b.PChainEpoch()), nil
}

func (b *postForkBlock) selectChildPChainHeight(ctx context.Context) (uint64, error) {
	return b.vm.selectChildPChainHeight(ctx, b.PChainHeight())
}

func (b *postForkBlock) getStatelessBlk() block.Block {
	// Return the embedded stateless block.SignedBlock
	return b.SignedBlock
}
