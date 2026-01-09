// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package proposervm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/consensus"
	chainblock "github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/vm/vms/proposervm/block"
	"github.com/luxfi/vm/vms/proposervm/lp181"
	"github.com/luxfi/vm/vms/proposervm/proposer"
)

const (
	// allowable block issuance in the future
	maxSkew = 10 * time.Second
)

var (
	errUnsignedChild            = errors.New("expected child to be signed")
	errUnexpectedBlockType      = errors.New("unexpected proposer block type")
	errInnerParentMismatch      = errors.New("inner parentID didn't match expected parent")
	errTimeNotMonotonic         = errors.New("time must monotonically increase")
	errPChainHeightNotMonotonic = errors.New("non monotonically increasing P-chain height")
	errPChainHeightNotReached   = errors.New("block P-chain height larger than current P-chain height")
	errTimeTooAdvanced          = errors.New("time is too far advanced")
	errEpochMismatch            = errors.New("epoch mismatch")
	errProposerWindowNotStarted = errors.New("proposer window hasn't started")
	errUnexpectedProposer       = errors.New("unexpected proposer for current window")
	errProposerMismatch         = errors.New("proposer mismatch")
	errProposersNotActivated    = errors.New("proposers haven't been activated yet")
	errPChainHeightTooLow       = errors.New("block P-chain height is too low")
	errNotOracle                = errors.New("block is not an oracle block")
)

// OracleBlock is a block that can return multiple child options
type OracleBlock interface {
	chainblock.Block
	Options(context.Context) ([2]chainblock.Block, error)
}

// Convert chainblock.Epoch (consensus) to block.Epoch (proposervm stateless block)
func toBlockEpoch(ce chainblock.Epoch) block.Epoch {
	return block.Epoch{
		PChainHeight: ce.PChainHeight,
		Number:       ce.Number,
		StartTime:    ce.StartTime,
	}
}

// Convert block.Epoch (proposervm stateless block) to chainblock.Epoch (consensus)
func toChainBlockEpoch(be block.Epoch) chainblock.Epoch {
	return chainblock.Epoch{
		PChainHeight: be.PChainHeight,
		Number:       be.Number,
		StartTime:    be.StartTime,
	}
}

type Block interface {
	chainblock.Block

	getInnerBlk() chainblock.Block

	// After a state sync, we may need to update last accepted block data
	// without propagating any changes to the innerVM.
	// acceptOuterBlk and acceptInnerBlk allow controlling acceptance of outer
	// and inner blocks.
	acceptOuterBlk() error
	acceptInnerBlk(context.Context) error

	verifyPreForkChild(ctx context.Context, child *preForkBlock) error
	verifyPostForkChild(ctx context.Context, child *postForkBlock) error
	verifyPostForkOption(ctx context.Context, child *postForkOption) error

	buildChild(context.Context) (Block, error)

	pChainHeight(context.Context) (uint64, error)
	pChainEpoch(context.Context) (chainblock.Epoch, error)
	selectChildPChainHeight(context.Context) (uint64, error)
}

type PostForkBlock interface {
	Block

	getStatelessBlk() block.Block
	setInnerBlk(chainblock.Block)
}

// field of postForkBlock and postForkOption
type postForkCommonComponents struct {
	vm       *VM
	innerBlk chainblock.Block
}

// Return the inner block's height
func (p *postForkCommonComponents) Height() uint64 {
	return p.innerBlk.Height()
}

// Verify returns nil if:
// 1) [p]'s inner block is not an oracle block
// 2) [child]'s P-Chain height >= [parentPChainHeight]
// 3) [p]'s inner block is the parent of [c]'s inner block
// 4) [child]'s timestamp isn't before [p]'s timestamp
// 5) [child]'s timestamp is within the skew bound
// 6) [childPChainHeight] <= the current P-Chain height
// 7) [child]'s timestamp is within its proposer's window
// 8) [child] has a valid signature from its proposer
// 9) [child]'s inner block is valid
// 10) [child] has the expected epoch
func (p *postForkCommonComponents) Verify(
	ctx context.Context,
	parentTimestamp time.Time,
	parentPChainHeight uint64,
	parentEpoch chainblock.Epoch,
	child *postForkBlock,
) error {
	if err := verifyIsNotOracleBlock(ctx, p.innerBlk); err != nil {
		return err
	}

	childPChainHeight := child.PChainHeight()
	if childPChainHeight < parentPChainHeight {
		return errPChainHeightNotMonotonic
	}

	expectedInnerParentID := p.innerBlk.ID()
	innerParentID := child.innerBlk.Parent()
	if innerParentID != expectedInnerParentID {
		return errInnerParentMismatch
	}

	childTimestamp := child.Timestamp()
	// Check timestamp monotonicity first
	if childTimestamp.Before(parentTimestamp) {
		return errTimeNotMonotonic
	}

	childEpoch := child.PChainEpoch()

	// Check timestamp is not too far in the future
	maxTimestamp := p.vm.Time().Add(maxSkew)
	if childTimestamp.After(maxTimestamp) {
		return errTimeTooAdvanced
	}

	// FIX 1: Consolidate all P-chain dependent validations into single block
	if p.vm.consensusState == uint32(consensus.Ready) {
		// All P-chain dependent validations here - only when synced
		// 1. Epoch validation
		if expected := lp181.NewEpoch(p.vm.Upgrades, parentPChainHeight, toBlockEpoch(parentEpoch), parentTimestamp, childTimestamp); childEpoch != expected {
			return fmt.Errorf("%w: epoch %v != expected %v", errEpochMismatch, childEpoch, expected)
		}

		// 2. P-chain height check
		currentPChainHeight, err := p.vm.validatorState.GetCurrentHeight(ctx)
		if err != nil {
			p.vm.logger.Error("block verification failed",
				log.String("reason", "failed to get current P-Chain height"),
				log.Stringer("blkID", child.ID()),
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

		// 3. Proposer window validation
		var shouldHaveProposer bool
		if p.vm.Upgrades.IsDurangoActivated(parentTimestamp) {
			shouldHaveProposer, err = p.verifyPostDurangoBlockDelay(ctx, parentTimestamp, parentPChainHeight, child)
		} else {
			shouldHaveProposer, err = p.verifyPreDurangoBlockDelay(ctx, parentTimestamp, parentPChainHeight, child)
		}
		if err != nil {
			return err
		}

		hasProposer := child.SignedBlock.Proposer() != ids.EmptyNodeID
		if shouldHaveProposer != hasProposer {
			return fmt.Errorf("%w: shouldHaveProposer (%v) != hasProposer (%v)", errProposerMismatch, shouldHaveProposer, hasProposer)
		}

		p.vm.logger.Debug("verified post-fork block",
			log.Stringer("blkID", child.ID()),
			log.Time("parentTimestamp", parentTimestamp),
			log.Time("blockTimestamp", childTimestamp),
		)
	}

	var contextPChainHeight uint64
	switch {
	case p.vm.Upgrades.IsGraniteActivated(childTimestamp):
		contextPChainHeight = childEpoch.PChainHeight
	case p.vm.Upgrades.IsEtnaActivated(childTimestamp):
		contextPChainHeight = childPChainHeight
	default:
		contextPChainHeight = parentPChainHeight
	}

	return p.vm.verifyAndRecordInnerBlk(
		ctx,
		&chainblock.Context{
			PChainHeight: contextPChainHeight,
		},
		child,
	)
}

// Return the child (a *postForkBlock) of this block
func (p *postForkCommonComponents) buildChild(
	ctx context.Context,
	parentID ids.ID,
	parentTimestamp time.Time,
	parentPChainHeight uint64,
	parentEpoch chainblock.Epoch,
) (Block, error) {
	// Child's timestamp is the later of now and this block's timestamp
	newTimestamp := p.vm.Time().Truncate(time.Second)
	if newTimestamp.Before(parentTimestamp) {
		newTimestamp = parentTimestamp
	}

	// The child's P-Chain height is proposed as the optimal P-Chain height that
	// is at least the parent's P-Chain height
	pChainHeight, err := p.vm.selectChildPChainHeight(ctx, parentPChainHeight)
	if err != nil {
		p.vm.logger.Error("unexpected build block failure",
			log.String("reason", "failed to calculate optimal P-chain height"),
			log.Stringer("parentID", parentID),
			log.Err(err),
		)
		return nil, err
	}

	var shouldBuildSignedBlock bool
	if p.vm.Upgrades.IsDurangoActivated(parentTimestamp) {
		shouldBuildSignedBlock, err = p.shouldBuildSignedBlockPostDurango(
			ctx,
			parentID,
			parentTimestamp,
			parentPChainHeight,
			newTimestamp,
		)
	} else {
		shouldBuildSignedBlock, err = p.shouldBuildSignedBlockPreDurango(
			ctx,
			parentID,
			parentTimestamp,
			parentPChainHeight,
			newTimestamp,
		)
	}
	if err != nil {
		return nil, err
	}

	epoch := lp181.NewEpoch(p.vm.Upgrades, parentPChainHeight, toBlockEpoch(parentEpoch), parentTimestamp, newTimestamp)

	var contextPChainHeight uint64
	switch {
	case p.vm.Upgrades.IsGraniteActivated(newTimestamp):
		contextPChainHeight = epoch.PChainHeight
	case p.vm.Upgrades.IsEtnaActivated(newTimestamp):
		contextPChainHeight = pChainHeight
	default:
		contextPChainHeight = parentPChainHeight
	}

	var innerBlock chainblock.Block
	if p.vm.blockBuilderVM != nil {
		builtBlock, err := p.vm.blockBuilderVM.BuildBlockWithContext(ctx, &chainblock.Context{
			PChainHeight: contextPChainHeight,
		})
		if err != nil {
			return nil, err
		}
		innerBlock = builtBlock
	} else {
		engineBlock, err := p.vm.ChainVM.BuildBlock(ctx)
		if err != nil {
			return nil, err
		}
		innerBlock = &reverseBlockAdapter{Block: engineBlock}
	}

	// Build the child
	var statelessChild block.SignedBlock
	if shouldBuildSignedBlock {
		statelessChild, err = block.Build(
			parentID,
			newTimestamp,
			pChainHeight,
			epoch,
			p.vm.StakingCertLeaf,
			innerBlock.Bytes(),
			p.vm.ctx.ChainID,
			p.vm.StakingLeafSigner,
		)
	} else {
		statelessChild, err = block.BuildUnsigned(
			parentID,
			newTimestamp,
			pChainHeight,
			epoch,
			innerBlock.Bytes(),
		)
	}
	if err != nil {
		p.vm.logger.Error("unexpected build block failure",
			log.String("reason", "failed to generate proposervm block header"),
			log.Stringer("parentID", parentID),
			log.Stringer("blkID", innerBlock.ID()),
			log.Err(err),
		)
		return nil, err
	}

	child := &postForkBlock{
		SignedBlock: statelessChild,
		postForkCommonComponents: postForkCommonComponents{
			vm:       p.vm,
			innerBlk: innerBlock,
		},
	}

	p.vm.logger.Info("built block",
		log.Stringer("blkID", child.ID()),
		log.Stringer("innerBlkID", innerBlock.ID()),
		log.Uint64("height", child.Height()),
		log.Uint64("pChainHeight", pChainHeight),
		log.Time("parentTimestamp", parentTimestamp),
		log.Time("blockTimestamp", newTimestamp),
		log.Reflect("epoch", epoch),
	)
	return child, nil
}

func (p *postForkCommonComponents) getInnerBlk() chainblock.Block {
	return p.innerBlk
}

func (p *postForkCommonComponents) setInnerBlk(innerBlk chainblock.Block) {
	p.innerBlk = innerBlk
}

func verifyIsOracleBlock(ctx context.Context, b chainblock.Block) error {
	oracle, ok := b.(OracleBlock)
	if !ok {
		return fmt.Errorf(
			"%w: expected block %s to be an OracleBlock but it's a %T",
			errUnexpectedBlockType, b.ID(), b,
		)
	}
	_, err := oracle.Options(ctx)
	return err
}

func verifyIsNotOracleBlock(ctx context.Context, b chainblock.Block) error {
	oracle, ok := b.(OracleBlock)
	if !ok {
		return nil
	}
	_, err := oracle.Options(ctx)
	switch err {
	case nil:
		return fmt.Errorf(
			"%w: expected block %s not to be an oracle block but it's a %T",
			errUnexpectedBlockType, b.ID(), b,
		)
	case errNotOracle:
		return nil
	default:
		return err
	}
}

func (p *postForkCommonComponents) verifyPreDurangoBlockDelay(
	ctx context.Context,
	parentTimestamp time.Time,
	parentPChainHeight uint64,
	blk *postForkBlock,
) (bool, error) {
	var (
		blkTimestamp = blk.Timestamp()
		childHeight  = blk.Height()
		proposerID   = blk.Proposer()
	)
	minDelay, err := p.vm.Windower.Delay(
		ctx,
		childHeight,
		parentPChainHeight,
		proposerID,
		proposer.MaxVerifyWindows,
	)
	if err != nil {
		p.vm.logger.Error("unexpected block verification failure",
			log.String("reason", "failed to calculate required timestamp delay"),
			log.Stringer("blkID", blk.ID()),
			log.Err(err),
		)
		return false, err
	}

	delay := blkTimestamp.Sub(parentTimestamp)
	if delay < minDelay {
		return false, fmt.Errorf("%w: delay %s < minDelay %s", errProposerWindowNotStarted, delay, minDelay)
	}

	return delay < proposer.MaxVerifyDelay, nil
}

func (p *postForkCommonComponents) verifyPostDurangoBlockDelay(
	ctx context.Context,
	parentTimestamp time.Time,
	parentPChainHeight uint64,
	blk *postForkBlock,
) (bool, error) {
	var (
		blkTimestamp = blk.Timestamp()
		blkHeight    = blk.Height()
		currentSlot  = proposer.TimeToSlot(parentTimestamp, blkTimestamp)
		proposerID   = blk.Proposer()
	)
	// populate the slot for the block.
	blk.slot = &currentSlot

	// find the expected proposer
	expectedProposerID, err := p.vm.Windower.ExpectedProposer(
		ctx,
		blkHeight,
		parentPChainHeight,
		currentSlot,
	)
	switch {
	case errors.Is(err, proposer.ErrAnyoneCanPropose):
		return false, nil // block should be unsigned
	case err != nil:
		p.vm.logger.Error("unexpected block verification failure",
			log.String("reason", "failed to calculate expected proposer"),
			log.Stringer("blkID", blk.ID()),
			log.Err(err),
		)
		return false, err
	case expectedProposerID == proposerID:
		return true, nil // block should be signed
	default:
		return false, fmt.Errorf("%w: slot %d expects %s", errUnexpectedProposer, currentSlot, expectedProposerID)
	}
}

func (p *postForkCommonComponents) shouldBuildSignedBlockPostDurango(
	ctx context.Context,
	parentID ids.ID,
	parentTimestamp time.Time,
	parentPChainHeight uint64,
	newTimestamp time.Time,
) (bool, error) {
	parentHeight := p.innerBlk.Height()
	currentSlot := proposer.TimeToSlot(parentTimestamp, newTimestamp)
	expectedProposerID, err := p.vm.Windower.ExpectedProposer(
		ctx,
		parentHeight+1,
		parentPChainHeight,
		currentSlot,
	)
	switch {
	case errors.Is(err, proposer.ErrAnyoneCanPropose):
		return false, nil // build an unsigned block
	case err != nil:
		p.vm.logger.Error("unexpected build block failure",
			log.String("reason", "failed to calculate expected proposer"),
			log.Stringer("parentID", parentID),
			log.Err(err),
		)
		return false, err
	case expectedProposerID == p.vm.ctx.NodeID:
		return true, nil // build a signed block
	}

	// It's not our turn to propose a block yet. This is likely caused by having
	// previously notified the consensus engine to attempt to build a block on
	// top of a block that is no longer the preferred block.
	p.vm.logger.Debug("build block dropped",
		log.Time("parentTimestamp", parentTimestamp),
		log.Time("blockTimestamp", newTimestamp),
		log.Uint64("slot", currentSlot),
		log.Stringer("expectedProposer", expectedProposerID),
	)
	return false, fmt.Errorf("%w: slot %d expects %s", errUnexpectedProposer, currentSlot, expectedProposerID)
}

func (p *postForkCommonComponents) shouldBuildSignedBlockPreDurango(
	ctx context.Context,
	parentID ids.ID,
	parentTimestamp time.Time,
	parentPChainHeight uint64,
	newTimestamp time.Time,
) (bool, error) {
	delay := newTimestamp.Sub(parentTimestamp)
	if delay >= proposer.MaxBuildDelay {
		return false, nil // time for any node to build an unsigned block
	}

	parentHeight := p.innerBlk.Height()
	proposerID := p.vm.ctx.NodeID
	minDelay, err := p.vm.Windower.Delay(ctx, parentHeight+1, parentPChainHeight, proposerID, proposer.MaxBuildWindows)
	if err != nil {
		p.vm.logger.Error("unexpected build block failure",
			log.String("reason", "failed to calculate required timestamp delay"),
			log.Stringer("parentID", parentID),
			log.Err(err),
		)
		return false, err
	}

	if delay >= minDelay {
		// it's time for this node to propose a block. It'll be signed or
		// unsigned depending on the delay
		return delay < proposer.MaxVerifyDelay, nil
	}

	// It's not our turn to propose a block yet. This is likely caused by having
	// previously notified the consensus engine to attempt to build a block on
	// top of a block that is no longer the preferred block.
	p.vm.logger.Debug("build block dropped",
		log.Time("parentTimestamp", parentTimestamp),
		log.Duration("minDelay", minDelay),
		log.Time("blockTimestamp", newTimestamp),
	)
	return false, fmt.Errorf("%w: delay %s < minDelay %s", errProposerWindowNotStarted, delay, minDelay)
}
