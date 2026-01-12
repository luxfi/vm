// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/luxfi/metric"
	"github.com/stretchr/testify/require"

	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/chain/blocktest"
)

const (
	defaultBlockCacheSize = 256
)

var (
	errCantBuildBlock       = errors.New("can't build new block")
	errVerify               = errors.New("verify failed")
	errAccept               = errors.New("accept failed")
	errReject               = errors.New("reject failed")
	errUnexpectedBlockBytes = errors.New("unexpected block bytes")
)

// testBlockAdapter wraps a blocktest.Block to implement the Block interface
type testBlockAdapter struct {
	*blocktest.Block
	verifyErr error
	acceptErr error
	rejectErr error
}

// Override Verify to handle the test error
func (b *testBlockAdapter) Verify(ctx context.Context) error {
	if b.verifyErr != nil {
		return b.verifyErr
	}
	return b.Block.Verify(ctx)
}

// Override Accept to handle the test error
func (b *testBlockAdapter) Accept(ctx context.Context) error {
	if b.acceptErr != nil {
		return b.acceptErr
	}
	return b.Block.Accept(ctx)
}

// Override Reject to handle the test error
func (b *testBlockAdapter) Reject(ctx context.Context) error {
	if b.rejectErr != nil {
		return b.rejectErr
	}
	return b.Block.Reject(ctx)
}

// NewTestBlock returns a new test block with height, bytes, and ID derived from [i]
// and using [parentID] as the parent block ID
func NewTestBlock(i uint64, parentID ids.ID) *blocktest.Block {
	b := []byte{byte(i)}
	id := hash.ComputeHash256Array(b)
	return &blocktest.Block{
		IDV:     id,
		HeightV: i,
		ParentV: parentID,
		BytesV:  b,
		StatusV: blocktest.Unknown,
	}
}

// NewTestBlocks generates [numBlocks] consecutive blocks
func NewTestBlocks(numBlocks uint64) []*blocktest.Block {
	blks := make([]*blocktest.Block, 0, numBlocks)
	parentID := ids.Empty
	for i := uint64(0); i < numBlocks; i++ {
		blks = append(blks, NewTestBlock(i, parentID))
		parent := blks[len(blks)-1]
		parentID = parent.ID()
	}

	return blks
}

func createInternalBlockFuncs(blks []*blocktest.Block) (
	func(ctx context.Context, blkID ids.ID) (block.Block, error),
	func(ctx context.Context, b []byte) (block.Block, error),
) {
	blkMap := make(map[ids.ID]*blocktest.Block)
	blkBytesMap := make(map[string]*blocktest.Block)
	adapterMap := make(map[ids.ID]*testBlockAdapter)

	// Create adapters for all blocks upfront
	for _, blk := range blks {
		blkMap[blk.ID()] = blk
		blkBytes := blk.Bytes()
		blkBytesMap[string(blkBytes)] = blk
		adapterMap[blk.ID()] = &testBlockAdapter{Block: blk}
	}

	getBlock := func(_ context.Context, id ids.ID) (block.Block, error) {
		blk, ok := blkMap[id]
		if !ok || blk.StatusV == blocktest.Unknown {
			return nil, database.ErrNotFound
		}

		return adapterMap[id], nil
	}

	parseBlk := func(_ context.Context, b []byte) (block.Block, error) {
		blk, ok := blkBytesMap[string(b)]
		if !ok {
			return nil, fmt.Errorf("%w: %x", errUnexpectedBlockBytes, b)
		}
		if blk.StatusV == blocktest.Unknown {
			blk.StatusV = blocktest.Processing
		}
		blkMap[blk.ID()] = blk

		return adapterMap[blk.ID()], nil
	}

	return getBlock, parseBlk
}

func cantBuildBlock(context.Context) (block.Block, error) {
	return nil, errCantBuildBlock
}

// checkProcessingBlock checks that [blk] is of the correct type and is
// correctly uniquified when calling GetBlock and ParseBlock.
func checkProcessingBlock(t *testing.T, s *State, blk block.Block) {
	require := require.New(t)

	require.IsType(&BlockWrapper{}, blk)

	parsedBlk, err := s.ParseBlock(context.Background(), blk.Bytes())
	require.NoError(err)
	require.Equal(blk.ID(), parsedBlk.ID())
	require.Equal(blk.Bytes(), parsedBlk.Bytes())
	require.Equal(blk, parsedBlk)

	getBlk, err := s.GetBlock(context.Background(), blk.ID())
	require.NoError(err)
	require.Equal(parsedBlk, getBlk)
}

// checkDecidedBlock asserts that [blk] is returned with the correct status by ParseBlock
// and GetBlock.
// expectedStatus should be either Accepted or Rejected.
func checkDecidedBlock(t *testing.T, s *State, blk block.Block, cached bool) {
	require := require.New(t)

	require.IsType(&BlockWrapper{}, blk)

	if cached {
		_, ok := s.decidedBlocks.Get(blk.ID())
		require.True(ok)
	}

	parsedBlk, err := s.ParseBlock(context.Background(), blk.Bytes())
	require.NoError(err)
	require.Equal(blk.ID(), parsedBlk.ID())
	require.Equal(blk.Bytes(), parsedBlk.Bytes())

	_, ok := s.decidedBlocks.Get(blk.ID())
	require.True(ok)

	// If the block should be in the cache, assert that the returned block is identical to [blk]
	if cached {
		require.Equal(blk, parsedBlk)
	}

	getBlk, err := s.GetBlock(context.Background(), blk.ID())
	require.NoError(err)
	require.Equal(blk.ID(), getBlk.ID())
	require.Equal(blk.Bytes(), getBlk.Bytes())

	// Since ParseBlock should have triggered a cache hit, assert that the block is identical
	// to the parsed block.
	require.Equal(parsedBlk, getBlk)
}

func TestState(t *testing.T) {
	require := require.New(t)

	testBlks := NewTestBlocks(3)
	genesisBlock := testBlks[0]
	genesisBlock.StatusV = blocktest.Accepted
	blk1 := testBlks[1]
	blk2 := testBlks[2]
	// Need to create a block with a different bytes and hash here
	// to generate a conflict with blk2
	blk3 := NewTestBlock(3, blk1.ID())
	testBlks = append(testBlks, blk3)

	getBlock, parseBlock := createInternalBlockFuncs(testBlks)
	chainState := NewState(&Config{
		DecidedCacheSize:    defaultBlockCacheSize,
		MissingCacheSize:    defaultBlockCacheSize,
		UnverifiedCacheSize: defaultBlockCacheSize,
		BytesToIDCacheSize:  defaultBlockCacheSize,
		LastAcceptedBlock:   genesisBlock,
		GetBlock:            getBlock,
		UnmarshalBlock:      parseBlock,
		BuildBlock:          cantBuildBlock,
	})

	lastAccepted, err := chainState.LastAccepted(context.Background())
	require.NoError(err)
	require.Equal(genesisBlock.ID(), lastAccepted)

	wrappedGenesisBlk, err := chainState.GetBlock(context.Background(), genesisBlock.ID())
	require.NoError(err)

	// Check that a cache miss on a block is handled correctly
	_, err = chainState.GetBlock(context.Background(), blk1.ID())
	require.ErrorIs(err, database.ErrNotFound)

	// Parse and verify blk1 and blk2
	parsedBlk1, err := chainState.ParseBlock(context.Background(), blk1.Bytes())
	require.NoError(err)
	require.NoError(parsedBlk1.Verify(context.Background()))

	parsedBlk2, err := chainState.ParseBlock(context.Background(), blk2.Bytes())
	require.NoError(err)
	require.NoError(parsedBlk2.Verify(context.Background()))

	// Check that the verified blocks have been placed in the processing map
	require.Len(chainState.verifiedBlocks, 2)

	parsedBlk3, err := chainState.ParseBlock(context.Background(), blk3.Bytes())
	require.NoError(err)
	getBlk3, err := chainState.GetBlock(context.Background(), blk3.ID())
	require.NoError(err)
	require.Equal(parsedBlk3.ID(), getBlk3.ID(), "State GetBlock returned the wrong block")

	// Check that parsing blk3 does not add it to processing blocks since it has
	// not been verified.
	require.Len(chainState.verifiedBlocks, 2)

	require.NoError(parsedBlk3.Verify(context.Background()))
	// Check that blk3 has been added to processing blocks.
	require.Len(chainState.verifiedBlocks, 3)

	// Decide the blocks and ensure they are removed from the processing blocks map
	require.NoError(parsedBlk1.Accept(context.Background()))
	require.NoError(parsedBlk2.Accept(context.Background()))
	require.NoError(parsedBlk3.Reject(context.Background()))

	require.Empty(chainState.verifiedBlocks)

	// Check that the last accepted block was updated correctly
	lastAcceptedID, err := chainState.LastAccepted(context.Background())
	require.NoError(err)
	require.Equal(blk2.ID(), lastAcceptedID)
	require.Equal(blk2.ID(), chainState.LastAcceptedBlock().ID())

	// Flush the caches to ensure decided blocks are handled correctly on cache misses.
	chainState.Flush()
	checkDecidedBlock(t, chainState, wrappedGenesisBlk, false)
	checkDecidedBlock(t, chainState, parsedBlk1, false)
	checkDecidedBlock(t, chainState, parsedBlk2, false)
	// parsedBlk3 was rejected - check it exists in storage
	getBlk3AfterFlush, err := chainState.GetBlock(context.Background(), blk3.ID())
	require.NoError(err)
	require.Equal(parsedBlk3.ID(), getBlk3AfterFlush.ID())
}

func TestBuildBlock(t *testing.T) {
	require := require.New(t)

	testBlks := NewTestBlocks(2)
	genesisBlock := testBlks[0]
	genesisBlock.StatusV = blocktest.Accepted
	blk1 := testBlks[1]

	getBlock, parseBlock := createInternalBlockFuncs(testBlks)
	buildBlock := func(context.Context) (block.Block, error) {
		// Once the block is built, mark it as processing
		blk1.StatusV = blocktest.Processing
		return blk1, nil
	}

	chainState := NewState(&Config{
		DecidedCacheSize:    defaultBlockCacheSize,
		MissingCacheSize:    defaultBlockCacheSize,
		UnverifiedCacheSize: defaultBlockCacheSize,
		BytesToIDCacheSize:  defaultBlockCacheSize,
		LastAcceptedBlock:   genesisBlock,
		GetBlock:            getBlock,
		UnmarshalBlock:      parseBlock,
		BuildBlock:          buildBlock,
	})

	builtBlk, err := chainState.BuildBlock(context.Background())
	require.NoError(err)
	require.Empty(chainState.verifiedBlocks)

	require.NoError(builtBlk.Verify(context.Background()))
	require.Len(chainState.verifiedBlocks, 1)

	checkProcessingBlock(t, chainState, builtBlk)

	require.NoError(builtBlk.Accept(context.Background()))

	checkDecidedBlock(t, chainState, builtBlk, true)
}

func TestStateDecideBlock(t *testing.T) {
	require := require.New(t)

	testBlks := NewTestBlocks(4)
	genesisBlock := testBlks[0]
	genesisBlock.StatusV = blocktest.Accepted
	badAcceptBlk := testBlks[1]
	badVerifyBlk := testBlks[2]
	badVerifyBlk.ErrV = errVerify
	badRejectBlk := testBlks[3]
	getBlock, parseBlock := createInternalBlockFuncs(testBlks)

	// Custom wrapper to make badAcceptBlk fail on Accept but not Verify
	originalGetBlock := getBlock
	getBlock = func(ctx context.Context, id ids.ID) (block.Block, error) {
		blk, err := originalGetBlock(ctx, id)
		if err != nil {
			return nil, err
		}
		if id == badAcceptBlk.ID() {
			return &testBlockAdapter{Block: badAcceptBlk, acceptErr: errAccept}, nil
		}
		if id == badRejectBlk.ID() {
			return &testBlockAdapter{Block: badRejectBlk, rejectErr: errReject}, nil
		}
		return blk, nil
	}

	originalParseBlock := parseBlock
	parseBlock = func(ctx context.Context, b []byte) (block.Block, error) {
		blk, err := originalParseBlock(ctx, b)
		if err != nil {
			return nil, err
		}
		id := blk.ID()
		if id == badAcceptBlk.ID() {
			return &testBlockAdapter{Block: badAcceptBlk, acceptErr: errAccept}, nil
		}
		if id == badRejectBlk.ID() {
			return &testBlockAdapter{Block: badRejectBlk, rejectErr: errReject}, nil
		}
		return blk, nil
	}

	chainState := NewState(&Config{
		DecidedCacheSize:    defaultBlockCacheSize,
		MissingCacheSize:    defaultBlockCacheSize,
		UnverifiedCacheSize: defaultBlockCacheSize,
		BytesToIDCacheSize:  defaultBlockCacheSize,
		LastAcceptedBlock:   genesisBlock,
		GetBlock:            getBlock,
		UnmarshalBlock:      parseBlock,
		BuildBlock:          cantBuildBlock,
	})

	// Parse badVerifyBlk (which should fail verification)
	badBlk, err := chainState.ParseBlock(context.Background(), badVerifyBlk.Bytes())
	require.NoError(err)
	err = badBlk.Verify(context.Background())
	require.ErrorIs(err, errVerify)
	// Ensure a block that fails verification is not marked as processing
	require.Empty(chainState.verifiedBlocks)

	// Ensure that an error during block acceptance is propagated correctly
	badBlk, err = chainState.ParseBlock(context.Background(), badAcceptBlk.Bytes())
	require.NoError(err)
	require.NoError(badBlk.Verify(context.Background()))
	require.Len(chainState.verifiedBlocks, 1)

	err = badBlk.Accept(context.Background())
	require.ErrorIs(err, errAccept)

	// Ensure that an error during block reject is propagated correctly
	badBlk, err = chainState.ParseBlock(context.Background(), badRejectBlk.Bytes())
	require.NoError(err)
	require.NoError(badBlk.Verify(context.Background()))
	// Note: an error during block Accept/Reject is fatal, so it is undefined whether
	// the block that failed on Accept should be removed from processing or not. We allow
	// either case here to make this test more flexible.
	numProcessing := len(chainState.verifiedBlocks)
	require.Contains([]int{1, 2}, numProcessing)

	err = badBlk.Reject(context.Background())
	require.ErrorIs(err, errReject)
}

func TestStateParent(t *testing.T) {
	require := require.New(t)

	testBlks := NewTestBlocks(3)
	genesisBlock := testBlks[0]
	genesisBlock.StatusV = blocktest.Accepted
	blk1 := testBlks[1]
	blk2 := testBlks[2]

	getBlock, parseBlock := createInternalBlockFuncs(testBlks)
	chainState := NewState(&Config{
		DecidedCacheSize:    defaultBlockCacheSize,
		MissingCacheSize:    defaultBlockCacheSize,
		UnverifiedCacheSize: defaultBlockCacheSize,
		BytesToIDCacheSize:  defaultBlockCacheSize,
		LastAcceptedBlock:   genesisBlock,
		GetBlock:            getBlock,
		UnmarshalBlock:      parseBlock,
		BuildBlock:          cantBuildBlock,
	})

	parsedBlk2, err := chainState.ParseBlock(context.Background(), blk2.Bytes())
	require.NoError(err)

	missingBlk1ID := parsedBlk2.Parent()

	_, err = chainState.GetBlock(context.Background(), missingBlk1ID)
	require.ErrorIs(err, database.ErrNotFound)

	parsedBlk1, err := chainState.ParseBlock(context.Background(), blk1.Bytes())
	require.NoError(err)

	genesisBlkParentID := parsedBlk1.Parent()
	genesisBlkParent, err := chainState.GetBlock(context.Background(), genesisBlkParentID)
	require.NoError(err)
	checkDecidedBlock(t, chainState, genesisBlkParent, true)

	parentBlk1ID := parsedBlk2.Parent()
	parentBlk1, err := chainState.GetBlock(context.Background(), parentBlk1ID)
	require.NoError(err)
	checkProcessingBlock(t, chainState, parentBlk1)
}

func TestGetBlockInternal(t *testing.T) {
	require := require.New(t)
	testBlks := NewTestBlocks(1)
	genesisBlock := testBlks[0]
	genesisBlock.StatusV = blocktest.Accepted

	getBlock, parseBlock := createInternalBlockFuncs(testBlks)
	chainState := NewState(&Config{
		DecidedCacheSize:    defaultBlockCacheSize,
		MissingCacheSize:    defaultBlockCacheSize,
		UnverifiedCacheSize: defaultBlockCacheSize,
		BytesToIDCacheSize:  defaultBlockCacheSize,
		LastAcceptedBlock:   genesisBlock,
		GetBlock:            getBlock,
		UnmarshalBlock:      parseBlock,
		BuildBlock:          cantBuildBlock,
	})

	genesisBlockInternal := chainState.LastAcceptedBlockInternal()
	// The internal block might be wrapped in an adapter
	if adapter, ok := genesisBlockInternal.(*testBlockAdapter); ok {
		genesisBlockInternal = adapter.Block
	}
	require.IsType(&blocktest.Block{}, genesisBlockInternal)
	require.Equal(genesisBlock.ID(), genesisBlockInternal.ID())

	blk, err := chainState.GetBlockInternal(context.Background(), genesisBlock.ID())
	require.NoError(err)

	// The internal block might be wrapped in an adapter
	if adapter, ok := blk.(*testBlockAdapter); ok {
		blk = adapter.Block
	}
	require.IsType(&blocktest.Block{}, blk)
	require.Equal(genesisBlock.ID(), blk.ID())
}

func TestGetBlockError(t *testing.T) {
	require := require.New(t)

	testBlks := NewTestBlocks(2)
	genesisBlock := testBlks[0]
	genesisBlock.StatusV = blocktest.Accepted
	blk1 := testBlks[1]

	getBlock, parseBlock := createInternalBlockFuncs(testBlks)
	wrappedGetBlock := func(ctx context.Context, id ids.ID) (block.Block, error) {
		blk, err := getBlock(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("wrapping error to prevent caching miss: %w", err)
		}
		return blk, nil
	}
	chainState := NewState(&Config{
		DecidedCacheSize:    defaultBlockCacheSize,
		MissingCacheSize:    defaultBlockCacheSize,
		UnverifiedCacheSize: defaultBlockCacheSize,
		BytesToIDCacheSize:  defaultBlockCacheSize,
		LastAcceptedBlock:   genesisBlock,
		GetBlock:            wrappedGetBlock,
		UnmarshalBlock:      parseBlock,
		BuildBlock:          cantBuildBlock,
	})

	_, err := chainState.GetBlock(context.Background(), blk1.ID())
	require.ErrorIs(err, database.ErrNotFound)

	// Update the status to Processing, so that it will be returned by the
	// internal get block function.
	blk1.StatusV = blocktest.Processing
	blk, err := chainState.GetBlock(context.Background(), blk1.ID())
	require.NoError(err)
	require.Equal(blk1.ID(), blk.ID())
	checkProcessingBlock(t, chainState, blk)
}

func TestParseBlockError(t *testing.T) {
	testBlks := NewTestBlocks(1)
	genesisBlock := testBlks[0]
	genesisBlock.StatusV = blocktest.Accepted

	getBlock, parseBlock := createInternalBlockFuncs(testBlks)
	chainState := NewState(&Config{
		DecidedCacheSize:    defaultBlockCacheSize,
		MissingCacheSize:    defaultBlockCacheSize,
		UnverifiedCacheSize: defaultBlockCacheSize,
		BytesToIDCacheSize:  defaultBlockCacheSize,
		LastAcceptedBlock:   genesisBlock,
		GetBlock:            getBlock,
		UnmarshalBlock:      parseBlock,
		BuildBlock:          cantBuildBlock,
	})

	_, err := chainState.ParseBlock(context.Background(), []byte{255})
	require.ErrorIs(t, err, errUnexpectedBlockBytes)
}

func TestBuildBlockError(t *testing.T) {
	testBlks := NewTestBlocks(1)
	genesisBlock := testBlks[0]
	genesisBlock.StatusV = blocktest.Accepted

	getBlock, parseBlock := createInternalBlockFuncs(testBlks)
	chainState := NewState(&Config{
		DecidedCacheSize:    defaultBlockCacheSize,
		MissingCacheSize:    defaultBlockCacheSize,
		UnverifiedCacheSize: defaultBlockCacheSize,
		BytesToIDCacheSize:  defaultBlockCacheSize,
		LastAcceptedBlock:   genesisBlock,
		GetBlock:            getBlock,
		UnmarshalBlock:      parseBlock,
		BuildBlock:          cantBuildBlock,
	})

	_, err := chainState.BuildBlock(context.Background())
	require.ErrorIs(t, err, errCantBuildBlock)
}

func TestMeteredCache(t *testing.T) {
	require := require.New(t)

	testBlks := NewTestBlocks(1)
	genesisBlock := testBlks[0]
	genesisBlock.StatusV = blocktest.Accepted

	getBlock, parseBlock := createInternalBlockFuncs(testBlks)

	// First MeteredState with its own registry
	registry1 := metric.NewRegistry()
	config1 := &Config{
		DecidedCacheSize:    defaultBlockCacheSize,
		MissingCacheSize:    defaultBlockCacheSize,
		UnverifiedCacheSize: defaultBlockCacheSize,
		BytesToIDCacheSize:  defaultBlockCacheSize,
		LastAcceptedBlock:   genesisBlock,
		GetBlock:            getBlock,
		UnmarshalBlock:      parseBlock,
		BuildBlock:          cantBuildBlock,
	}
	_, err := NewMeteredState(registry1, config1)
	require.NoError(err)

	// Second MeteredState with a different registry - should succeed
	registry2 := metric.NewRegistry()
	config2 := &Config{
		DecidedCacheSize:    defaultBlockCacheSize,
		MissingCacheSize:    defaultBlockCacheSize,
		UnverifiedCacheSize: defaultBlockCacheSize,
		BytesToIDCacheSize:  defaultBlockCacheSize,
		LastAcceptedBlock:   genesisBlock,
		GetBlock:            getBlock,
		UnmarshalBlock:      parseBlock,
		BuildBlock:          cantBuildBlock,
	}
	_, err = NewMeteredState(registry2, config2)
	require.NoError(err)
}

// Test the bytesToIDCache
func TestStateBytesToIDCache(t *testing.T) {
	require := require.New(t)

	testBlks := NewTestBlocks(3)
	genesisBlock := testBlks[0]
	genesisBlock.StatusV = blocktest.Accepted
	blk1 := testBlks[1]
	blk2 := testBlks[2]

	getBlock, parseBlock := createInternalBlockFuncs(testBlks)
	buildBlock := func(context.Context) (block.Block, error) {
		require.FailNow("shouldn't have been called")
		return nil, nil
	}

	chainState := NewState(&Config{
		DecidedCacheSize:    0,
		MissingCacheSize:    0,
		UnverifiedCacheSize: 0,
		BytesToIDCacheSize:  1 + ids.IDLen, // Size of one block
		LastAcceptedBlock:   &testBlockAdapter{Block: genesisBlock},
		GetBlock:            getBlock,
		UnmarshalBlock:      parseBlock,
		BuildBlock:          buildBlock,
	})

	// Shouldn't have blk1 ID to start with
	_, err := chainState.GetBlock(context.Background(), blk1.ID())
	require.ErrorIs(err, database.ErrNotFound)
	_, ok := chainState.bytesToIDCache.Get(string(blk1.Bytes()))
	require.False(ok)

	// Parse blk1 from bytes
	_, err = chainState.ParseBlock(context.Background(), blk1.Bytes())
	require.NoError(err)

	// blk1 should be in cache now
	_, ok = chainState.bytesToIDCache.Get(string(blk1.Bytes()))
	require.True(ok)

	// Parse another block
	_, err = chainState.ParseBlock(context.Background(), blk2.Bytes())
	require.NoError(err)

	// Should have bumped blk1 from cache
	_, ok = chainState.bytesToIDCache.Get(string(blk2.Bytes()))
	require.True(ok)
	_, ok = chainState.bytesToIDCache.Get(string(blk1.Bytes()))
	require.False(ok)
}

// TestSetLastAcceptedBlock ensures chainState's last accepted block
// can be updated by calling [SetLastAcceptedBlock].
func TestSetLastAcceptedBlock(t *testing.T) {
	require := require.New(t)

	testBlks := NewTestBlocks(1)
	genesisBlock := testBlks[0]
	genesisBlock.StatusV = blocktest.Accepted

	postSetBlk1ParentID := hash.ComputeHash256Array([]byte{byte(199)})
	postSetBlk1 := NewTestBlock(200, postSetBlk1ParentID)
	postSetBlk2 := NewTestBlock(201, postSetBlk1.ID())

	// note we do not need to parse postSetBlk1 so it is omitted here
	testBlks = append(testBlks, postSetBlk2)

	getBlock, parseBlock := createInternalBlockFuncs(testBlks)
	chainState := NewState(&Config{
		DecidedCacheSize:    defaultBlockCacheSize,
		MissingCacheSize:    defaultBlockCacheSize,
		UnverifiedCacheSize: defaultBlockCacheSize,
		BytesToIDCacheSize:  defaultBlockCacheSize,
		LastAcceptedBlock:   genesisBlock,
		GetBlock:            getBlock,
		UnmarshalBlock:      parseBlock,
		BuildBlock:          cantBuildBlock,
	})
	lastAcceptedID, err := chainState.LastAccepted(context.Background())
	require.NoError(err)
	require.Equal(genesisBlock.ID(), lastAcceptedID)

	// call SetLastAcceptedBlock for postSetBlk1
	// Need to create adapter for postSetBlk1 since it's not in the original testBlks
	postSetBlk1Adapter := &testBlockAdapter{Block: postSetBlk1}
	require.NoError(chainState.SetLastAcceptedBlock(postSetBlk1Adapter))
	lastAcceptedID, err = chainState.LastAccepted(context.Background())
	require.NoError(err)
	require.Equal(postSetBlk1.ID(), lastAcceptedID)
	require.Equal(postSetBlk1.ID(), chainState.LastAcceptedBlock().ID())

	// ensure further blocks can be accepted
	parsedpostSetBlk2, err := chainState.ParseBlock(context.Background(), postSetBlk2.Bytes())
	require.NoError(err)
	require.NoError(parsedpostSetBlk2.Verify(context.Background()))
	require.NoError(parsedpostSetBlk2.Accept(context.Background()))
	lastAcceptedID, err = chainState.LastAccepted(context.Background())
	require.NoError(err)
	require.Equal(postSetBlk2.ID(), lastAcceptedID)
	require.Equal(postSetBlk2.ID(), chainState.LastAcceptedBlock().ID())

	checkDecidedBlock(t, chainState, parsedpostSetBlk2, false)
}

func TestSetLastAcceptedBlockWithProcessingBlocksErrors(t *testing.T) {
	require := require.New(t)

	testBlks := NewTestBlocks(5)
	genesisBlock := testBlks[0]
	genesisBlock.StatusV = blocktest.Accepted
	blk1 := testBlks[1]
	resetBlk := testBlks[4]

	getBlock, parseBlock := createInternalBlockFuncs(testBlks)
	buildBlock := func(context.Context) (block.Block, error) {
		// Once the block is built, mark it as processing
		genesisBlock.StatusV = blocktest.Processing
		return blk1, nil
	}

	chainState := NewState(&Config{
		DecidedCacheSize:    defaultBlockCacheSize,
		MissingCacheSize:    defaultBlockCacheSize,
		UnverifiedCacheSize: defaultBlockCacheSize,
		BytesToIDCacheSize:  defaultBlockCacheSize,
		LastAcceptedBlock:   genesisBlock,
		GetBlock:            getBlock,
		UnmarshalBlock:      parseBlock,
		BuildBlock:          buildBlock,
	})

	builtBlk, err := chainState.BuildBlock(context.Background())
	require.NoError(err)
	require.Empty(chainState.verifiedBlocks)

	require.NoError(builtBlk.Verify(context.Background()))
	require.Len(chainState.verifiedBlocks, 1)

	checkProcessingBlock(t, chainState, builtBlk)

	err = chainState.SetLastAcceptedBlock(&testBlockAdapter{Block: resetBlk})
	require.ErrorIs(err, errSetAcceptedWithProcessing)
}

func TestStateParseTransitivelyAcceptedBlock(t *testing.T) {
	require := require.New(t)

	testBlks := NewTestBlocks(3)
	genesisBlock := testBlks[0]
	genesisBlock.StatusV = blocktest.Accepted
	blk1 := testBlks[1]
	blk2 := testBlks[2]
	blk2.StatusV = blocktest.Accepted

	getBlock, parseBlock := createInternalBlockFuncs(testBlks)
	chainState := NewState(&Config{
		DecidedCacheSize:    defaultBlockCacheSize,
		MissingCacheSize:    defaultBlockCacheSize,
		UnverifiedCacheSize: defaultBlockCacheSize,
		BytesToIDCacheSize:  defaultBlockCacheSize,
		LastAcceptedBlock:   blk2,
		GetBlock:            getBlock,
		UnmarshalBlock:      parseBlock,
		BuildBlock:          cantBuildBlock,
	})

	parsedBlk1, err := chainState.ParseBlock(context.Background(), blk1.Bytes())
	require.NoError(err)
	require.Equal(blk1.Height(), parsedBlk1.Height())
}

func TestIsProcessing(t *testing.T) {
	require := require.New(t)

	testBlks := NewTestBlocks(2)
	genesisBlock := testBlks[0]
	genesisBlock.StatusV = blocktest.Accepted
	blk1 := testBlks[1]

	getBlock, parseBlock := createInternalBlockFuncs(testBlks)
	chainState := NewState(&Config{
		DecidedCacheSize:    defaultBlockCacheSize,
		MissingCacheSize:    defaultBlockCacheSize,
		UnverifiedCacheSize: defaultBlockCacheSize,
		BytesToIDCacheSize:  defaultBlockCacheSize,
		LastAcceptedBlock:   genesisBlock,
		GetBlock:            getBlock,
		UnmarshalBlock:      parseBlock,
		BuildBlock:          cantBuildBlock,
	})

	// Parse blk1
	parsedBlk1, err := chainState.ParseBlock(context.Background(), blk1.Bytes())
	require.NoError(err)

	// Check that it is not processing in consensus
	require.False(chainState.IsProcessing(parsedBlk1.ID()))

	// Verify blk1
	require.NoError(parsedBlk1.Verify(context.Background()))

	// Check that it is processing in consensus
	require.True(chainState.IsProcessing(parsedBlk1.ID()))

	// Accept blk1
	require.NoError(parsedBlk1.Accept(context.Background()))

	// Check that it is no longer processing in consensus
	require.False(chainState.IsProcessing(parsedBlk1.ID()))
}
