// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package indexer

import (
	"context"
	"time"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/vm/utils"
	"github.com/luxfi/vm/vms/proposervm/state"
)

// default number of heights to index before committing
const (
	defaultCommitFrequency = 1024
	// Sleep [sleepDurationMultiplier]x (10x) the amount of time we spend
	// processing the block to ensure the async indexing does not bottleneck the
	// node.
	sleepDurationMultiplier = 10
)

var _ HeightIndexer = (*heightIndexer)(nil)

type HeightIndexer interface {
	// Returns whether the height index is fully repaired.
	IsRepaired() bool

	// MarkRepaired atomically sets the indexing repaired state.
	MarkRepaired(isRepaired bool)

	// Resumes repairing of the height index from the checkpoint.
	RepairHeightIndex(context.Context) error
}

func NewHeightIndexer(
	server BlockServer,
	log log.Logger,
	indexState state.State,
) HeightIndexer {
	return newHeightIndexer(server, log, indexState)
}

func newHeightIndexer(
	server BlockServer,
	log log.Logger,
	indexState state.State,
) *heightIndexer {
	return &heightIndexer{
		server:          server,
		log:             log,
		state:           indexState,
		commitFrequency: defaultCommitFrequency,
	}
}

type heightIndexer struct {
	server BlockServer
	log    log.Logger

	jobDone utils.Atomic[bool]
	state   state.State

	commitFrequency int
}

func (hi *heightIndexer) IsRepaired() bool {
	return hi.jobDone.Get()
}

func (hi *heightIndexer) MarkRepaired(repaired bool) {
	hi.jobDone.Set(repaired)
}

// RepairHeightIndex ensures the height -> proBlkID height block index is well formed.
// Starting from the checkpoint, it will go back to chain++ activation fork
// or genesis. PreFork blocks will be handled by innerVM height index.
// RepairHeightIndex can take a non-trivial time to complete; hence we make sure
// the process has limited memory footprint, can be resumed from periodic checkpoints
// and works asynchronously without blocking the VM.
func (hi *heightIndexer) RepairHeightIndex(ctx context.Context) error {
	// Get the checkpoint (last accepted block)
	checkpointBlkID, err := hi.state.GetCheckpoint()
	if err == database.ErrNotFound {
		// No checkpoint set, nothing to repair
		hi.MarkRepaired(true)
		return nil
	}
	if err != nil {
		return err
	}

	// Get the checkpoint block to determine its height
	checkpointBlk, err := hi.server.GetFullPostForkBlock(ctx, checkpointBlkID)
	if err != nil {
		return err
	}

	// Start from checkpoint height and iterate backwards
	err = hi.doRepair(ctx, checkpointBlkID, checkpointBlk.Height())
	if err != nil {
		return err
	}

	// Flush the final state
	return hi.flush()
}

// if height index needs repairing, doRepair would do that. It
// iterates back via parents, checking and rebuilding height indexing.
// Note: batch commit is deferred to doRepair caller
func (hi *heightIndexer) doRepair(ctx context.Context, currentProBlkID ids.ID, lastIndexedHeight uint64) error {
	var (
		start           = time.Now()
		lastLogTime     = start
		indexedBlks     int
		lastIndexedBlks int
	)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		processingStart := time.Now()
		currentAcceptedBlk, err := hi.state.GetBlock(currentProBlkID)
		if err == database.ErrNotFound {
			// We have visited all the proposerVM blocks. Because we previously
			// verified that we needed to perform a repair, we know that this
			// will not happen on the first iteration. This guarantees that
			// forkHeight will be correctly initialized.
			forkHeight := lastIndexedHeight + 1
			if err := hi.state.SetForkHeight(forkHeight); err != nil {
				return err
			}
			// TODO: Checkpoint functionality removed
			// if err := hi.state.DeleteCheckpoint(); err != nil {
			// 	return err
			// }
			hi.MarkRepaired(true)

			// it will commit on exit
			hi.log.Info("indexing finished",
				log.Int("numIndexedBlocks", indexedBlks),
				log.Duration("duration", time.Since(start)),
				log.Uint64("forkHeight", forkHeight),
			)
			return nil
		}
		if err != nil {
			return err
		}

		// Keep memory footprint under control by committing when a size threshold is reached
		if indexedBlks-lastIndexedBlks > hi.commitFrequency {
			// Note: checkpoint must be the lowest block in the batch. This ensures that
			// checkpoint is the highest un-indexed block from which process would restart.
			// TODO: Checkpoint functionality removed
			// if err := hi.state.SetCheckpoint(currentProBlkID); err != nil {
			// 	return err
			// }

			if err := hi.flush(); err != nil {
				return err
			}

			hi.log.Debug("indexed blocks",
				log.Int("numIndexBlocks", indexedBlks),
			)
			lastIndexedBlks = indexedBlks
		}

		// Rebuild height block index.
		if err := hi.state.SetBlockIDAtHeight(lastIndexedHeight, currentProBlkID); err != nil {
			return err
		}

		// Periodically log progress
		indexedBlks++
		now := time.Now()
		if now.Sub(lastLogTime) > 15*time.Second {
			lastLogTime = now
			hi.log.Info("indexed blocks",
				log.Int("numIndexBlocks", indexedBlks),
				log.Uint64("lastIndexedHeight", lastIndexedHeight),
			)
		}

		// keep checking the parent
		currentProBlkID = currentAcceptedBlk.ParentID()
		lastIndexedHeight--

		processingDuration := time.Since(processingStart)
		// Sleep [sleepDurationMultiplier]x (5x) the amount of time we spend processing the block
		// to ensure the indexing does not bottleneck the node.
		time.Sleep(processingDuration * sleepDurationMultiplier)
	}
}

// flush writes the commits to the underlying DB
func (hi *heightIndexer) flush() error {
	// TODO: State interface no longer has Commit method
	// The commit should be handled by the versiondb layer
	// if err := hi.state.Commit(); err != nil {
	// 	return err
	// }
	return hi.server.Commit()
}
