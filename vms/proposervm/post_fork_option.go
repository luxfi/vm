// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package proposervm

import (
	"context"
	"time"

	"github.com/luxfi/log"

	chainblock "github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/vms/proposervm/block"
)

var _ PostForkBlock = (*postForkOption)(nil)

// The parent of a *postForkOption must be a *postForkBlock.
type postForkOption struct {
	block.Block
	postForkCommonComponents

	timestamp time.Time
}

// Status returns the status of the inner block
func (b *postForkOption) Status() uint8 {
	return b.innerBlk.Status()
}

// Height returns the height of the inner block - explicit to resolve ambiguity
func (b *postForkOption) Height() uint64 {
	return b.postForkCommonComponents.Height()
}

func (b *postForkOption) Timestamp() time.Time {
	if b.Height() <= b.vm.lastAcceptedHeight {
		return b.vm.lastAcceptedTime
	}
	return b.timestamp
}

func (b *postForkOption) Accept(ctx context.Context) error {
	if err := b.acceptOuterBlk(); err != nil {
		return err
	}
	return b.acceptInnerBlk(ctx)
}

func (b *postForkOption) acceptOuterBlk() error {
	return b.vm.acceptPostForkBlock(b)
}

func (b *postForkOption) acceptInnerBlk(ctx context.Context) error {
	// mark the inner block as accepted and all conflicting inner blocks as
	// rejected
	return b.vm.Tree.Accept(ctx, b.innerBlk)
}

func (b *postForkOption) Reject(ctx context.Context) error {
	// we do not reject the inner block here because that block may be contained
	// in the proposer block that causing this block to be rejected.

	delete(b.vm.verifiedBlocks, b.ID())
	return nil
}

func (b *postForkOption) Parent() ids.ID {
	return b.ParentID()
}

// If Verify returns nil, Accept or Reject is eventually called on [b] and
// [b.innerBlk].
func (b *postForkOption) Verify(ctx context.Context) error {
	parent, err := b.vm.getBlock(ctx, b.ParentID())
	if err != nil {
		return err
	}
	// Cast parent to PostForkBlock to get Timestamp
	if postForkParent, ok := parent.(PostForkBlock); ok {
		b.timestamp = postForkParent.Timestamp()
	} else {
		// For pre-fork blocks, use current time as fallback
		b.timestamp = b.vm.Time()
	}
	return parent.verifyPostForkOption(ctx, b)
}

func (*postForkOption) verifyPreForkChild(context.Context, *preForkBlock) error {
	// A *preForkBlock's parent must be a *preForkBlock
	return errUnsignedChild
}

func (b *postForkOption) verifyPostForkChild(ctx context.Context, child *postForkBlock) error {
	parentTimestamp := b.Timestamp()
	parentPChainHeight, err := b.pChainHeight(ctx)
	if err != nil {
		return err
	}
	parentEpoch, err := b.pChainEpoch(ctx)
	if err != nil {
		return err
	}

	return b.postForkCommonComponents.Verify(
		ctx,
		parentTimestamp,
		parentPChainHeight,
		parentEpoch,
		child,
	)
}

func (*postForkOption) verifyPostForkOption(context.Context, *postForkOption) error {
	// A *postForkOption's parent can't be a *postForkOption
	return errUnexpectedBlockType
}

func (b *postForkOption) buildChild(ctx context.Context) (Block, error) {
	parentID := b.ID()
	parentPChainHeight, err := b.pChainHeight(ctx)
	if err != nil {
		b.vm.logger.Error("unexpected build block failure",
			log.String("reason", "failed to fetch parent's P-chain height"),
			log.Stringer("parentID", parentID),
			log.Err(err),
		)
		return nil, err
	}
	parentEpoch, err := b.pChainEpoch(ctx)
	if err != nil {
		b.vm.logger.Error("unexpected build block failure",
			log.String("reason", "failed to fetch parent's epoch"),
			log.Stringer("parentID", parentID),
			log.Err(err),
		)
		return nil, err
	}

	return b.postForkCommonComponents.buildChild(
		ctx,
		parentID,
		b.Timestamp(),
		parentPChainHeight,
		parentEpoch,
	)
}

// This block's P-Chain height is its parent's P-Chain height
func (b *postForkOption) pChainHeight(ctx context.Context) (uint64, error) {
	parent, err := b.vm.getBlock(ctx, b.ParentID())
	if err != nil {
		return 0, err
	}
	return parent.pChainHeight(ctx)
}

func (b *postForkOption) pChainEpoch(ctx context.Context) (chainblock.Epoch, error) {
	parent, err := b.vm.getBlock(ctx, b.ParentID())
	if err != nil {
		return chainblock.Epoch{}, err
	}
	return parent.pChainEpoch(ctx)
}

func (b *postForkOption) selectChildPChainHeight(ctx context.Context) (uint64, error) {
	pChainHeight, err := b.pChainHeight(ctx)
	if err != nil {
		return 0, err
	}

	return b.vm.selectChildPChainHeight(ctx, pChainHeight)
}

func (b *postForkOption) getStatelessBlk() block.Block {
	// Return the embedded stateless block.Block
	return b.Block
}
