// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package indexer

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/consensus/core/choices"
	chainblock "github.com/luxfi/consensus/engine/chain/block"
	consensustest "github.com/luxfi/consensus/test/helpers"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/vm/vms/proposervm/block"
	"github.com/luxfi/vm/vms/proposervm/state"
)

// testBlock is a simple implementation for testing
type testBlock struct {
	consensustest.Decidable
	HeightV uint64
	AcceptF func() error
	RejectF func() error
}

func (b *testBlock) ID() ids.ID           { return b.IDV }
func (b *testBlock) Parent() ids.ID       { return ids.Empty }
func (b *testBlock) ParentID() ids.ID     { return ids.Empty }
func (b *testBlock) Height() uint64       { return b.HeightV }
func (b *testBlock) Timestamp() time.Time { return time.Now() }
func (b *testBlock) Bytes() []byte        { return nil }
func (b *testBlock) Status() uint8        { return uint8(b.StatusV) }
func (b *testBlock) Accept(context.Context) error {
	if b.AcceptF != nil {
		return b.AcceptF()
	}
	b.StatusV = choices.Accepted
	return nil
}
func (b *testBlock) Reject(context.Context) error {
	if b.RejectF != nil {
		return b.RejectF()
	}
	b.StatusV = choices.Rejected
	return nil
}
func (b *testBlock) Verify(context.Context) error { return nil }

func TestHeightBlockIndexPostFork(t *testing.T) {
	require := require.New(t)

	db := memdb.New()
	vdb := versiondb.New(db)
	storedState := state.New(vdb)

	// Build a chain of post fork blocks
	var (
		blkNumber = uint64(10)
		lastBlkID = ids.Empty.Prefix(0) // initially set to a dummyGenesisID
		proBlks   = make(map[ids.ID]chainblock.Block)
	)

	for blkHeight := uint64(1); blkHeight <= blkNumber; blkHeight++ {
		blockBytes := ids.Empty.Prefix(blkHeight + blkNumber + 1)
		dummyTS := time.Time{}
		dummyPCH := uint64(2022)

		// store postForkStatelessBlk in State ...
		postForkStatelessBlk, err := block.BuildUnsigned(
			lastBlkID,
			dummyTS,
			dummyPCH,
			block.Epoch{},
			blockBytes[:],
		)
		require.NoError(err)
		require.NoError(storedState.PutBlock(postForkStatelessBlk))

		// ... and create a corresponding test block just for block server
		postForkBlk := &testBlock{
			Decidable: consensustest.Decidable{
				IDV:     postForkStatelessBlk.ID(),
				StatusV: choices.Accepted,
			},
			HeightV: blkHeight,
		}
		proBlks[postForkStatelessBlk.ID()] = postForkBlk

		lastBlkID = postForkStatelessBlk.ID()
	}

	blkSrv := &TestBlockServer{
		CantGetFullPostForkBlock: true,
		CantCommit:               true,

		GetFullPostForkBlockF: func(_ context.Context, blkID ids.ID) (chainblock.Block, error) {
			blk, found := proBlks[blkID]
			if !found {
				return nil, database.ErrNotFound
			}
			return blk, nil
		},
		CommitF: func() error {
			return nil
		},
	}

	hIndex := newHeightIndexer(blkSrv,
		log.NoLog{},
		storedState,
	)
	hIndex.commitFrequency = 0 // commit each block

	// checkpoint last accepted block and show the whole chain in reindexed
	require.NoError(hIndex.state.SetCheckpoint(lastBlkID))
	require.NoError(hIndex.RepairHeightIndex(context.Background()))
	require.True(hIndex.IsRepaired())

	// check that height index is fully built
	loadedForkHeight, err := storedState.GetForkHeight()
	require.NoError(err)
	require.Equal(uint64(1), loadedForkHeight)
	for height := uint64(1); height <= blkNumber; height++ {
		_, err := storedState.GetBlockIDAtHeight(height)
		require.NoError(err)
	}
}

func TestHeightBlockIndexAcrossFork(t *testing.T) {
	require := require.New(t)

	db := memdb.New()
	vdb := versiondb.New(db)
	storedState := state.New(vdb)

	// Build a chain of post fork blocks
	var (
		blkNumber  = uint64(10)
		forkHeight = blkNumber / 2
		lastBlkID  = ids.Empty.Prefix(0) // initially set to a last pre fork blk
		proBlks    = make(map[ids.ID]chainblock.Block)
	)

	for blkHeight := forkHeight; blkHeight <= blkNumber; blkHeight++ {
		blockBytes := ids.Empty.Prefix(blkHeight + blkNumber + 1)
		dummyTS := time.Time{}
		dummyPCH := uint64(2022)

		// store postForkStatelessBlk in State ...
		postForkStatelessBlk, err := block.BuildUnsigned(
			lastBlkID,
			dummyTS,
			dummyPCH,
			block.Epoch{},
			blockBytes[:],
		)
		require.NoError(err)
		require.NoError(storedState.PutBlock(postForkStatelessBlk))

		// ... and create a corresponding test block just for block server
		postForkBlk := &testBlock{
			Decidable: consensustest.Decidable{
				IDV:     postForkStatelessBlk.ID(),
				StatusV: choices.Accepted,
			},
			HeightV: blkHeight,
		}
		proBlks[postForkStatelessBlk.ID()] = postForkBlk

		lastBlkID = postForkStatelessBlk.ID()
	}

	blkSrv := &TestBlockServer{
		CantGetFullPostForkBlock: true,
		CantCommit:               true,

		GetFullPostForkBlockF: func(_ context.Context, blkID ids.ID) (chainblock.Block, error) {
			blk, found := proBlks[blkID]
			if !found {
				return nil, database.ErrNotFound
			}
			return blk, nil
		},
		CommitF: func() error {
			return nil
		},
	}

	hIndex := newHeightIndexer(blkSrv,
		log.NoLog{},
		storedState,
	)
	hIndex.commitFrequency = 0 // commit each block

	// checkpoint last accepted block and show the whole chain in reindexed
	require.NoError(hIndex.state.SetCheckpoint(lastBlkID))
	require.NoError(hIndex.RepairHeightIndex(context.Background()))
	require.True(hIndex.IsRepaired())

	// check that height index is fully built
	loadedForkHeight, err := storedState.GetForkHeight()
	require.NoError(err)
	require.Equal(forkHeight, loadedForkHeight)
	for height := uint64(0); height < forkHeight; height++ {
		_, err := storedState.GetBlockIDAtHeight(height)
		require.ErrorIs(err, database.ErrNotFound)
	}
	for height := forkHeight; height <= blkNumber; height++ {
		_, err := storedState.GetBlockIDAtHeight(height)
		require.NoError(err)
	}
}

func TestHeightBlockIndexResumeFromCheckPoint(t *testing.T) {
	require := require.New(t)

	db := memdb.New()
	vdb := versiondb.New(db)
	storedState := state.New(vdb)

	// Build a chain of post fork blocks
	var (
		blkNumber  = uint64(10)
		forkHeight = blkNumber / 2
		lastBlkID  = ids.Empty.Prefix(0) // initially set to a last pre fork blk
		proBlks    = make(map[ids.ID]chainblock.Block)
	)

	for blkHeight := forkHeight; blkHeight <= blkNumber; blkHeight++ {
		blockBytes := ids.Empty.Prefix(blkHeight + blkNumber + 1)
		dummyTS := time.Time{}
		dummyPCH := uint64(2022)

		// store postForkStatelessBlk in State ...
		postForkStatelessBlk, err := block.BuildUnsigned(
			lastBlkID,
			dummyTS,
			dummyPCH,
			block.Epoch{},
			blockBytes[:],
		)
		require.NoError(err)
		require.NoError(storedState.PutBlock(postForkStatelessBlk))

		// ... and create a corresponding test block just for block server
		postForkBlk := &testBlock{
			Decidable: consensustest.Decidable{
				IDV:     postForkStatelessBlk.ID(),
				StatusV: choices.Accepted,
			},
			HeightV: blkHeight,
		}
		proBlks[postForkStatelessBlk.ID()] = postForkBlk

		lastBlkID = postForkStatelessBlk.ID()
	}

	blkSrv := &TestBlockServer{
		CantGetFullPostForkBlock: true,
		CantCommit:               true,

		GetFullPostForkBlockF: func(_ context.Context, blkID ids.ID) (chainblock.Block, error) {
			blk, found := proBlks[blkID]
			if !found {
				return nil, database.ErrNotFound
			}
			return blk, nil
		},
		CommitF: func() error {
			return nil
		},
	}

	hIndex := newHeightIndexer(blkSrv,
		log.NoLog{},
		storedState,
	)
	hIndex.commitFrequency = 0 // commit each block

	// pick a random block in the chain and checkpoint it;...
	rndPostForkHeight := rand.Intn(int(blkNumber-forkHeight)) + int(forkHeight) // #nosec G404
	var checkpointBlk chainblock.Block
	for _, blk := range proBlks {
		if blk.Height() != uint64(rndPostForkHeight) {
			continue // not the blk we are looking for
		}

		checkpointBlk = blk
		require.NoError(hIndex.state.SetCheckpoint(checkpointBlk.ID()))
		break
	}

	// perform repair and show index is built
	require.NoError(hIndex.RepairHeightIndex(context.Background()))
	require.True(hIndex.IsRepaired())

	// check that height index is fully built
	loadedForkHeight, err := storedState.GetForkHeight()
	require.NoError(err)
	require.Equal(forkHeight, loadedForkHeight)
	for height := forkHeight; height <= checkpointBlk.Height(); height++ {
		_, err := storedState.GetBlockIDAtHeight(height)
		require.NoError(err)
	}
}
