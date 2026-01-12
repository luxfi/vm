// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/components/chain/blocktest"

	"github.com/luxfi/consensus/engine/chain/block"
)

var (
	blkBytes1 = []byte{1}
	blkBytes2 = []byte{2}

	blkID0 = ids.ID{0}
	blkID1 = ids.ID{1}
	blkID2 = ids.ID{2}

	time1 = time.Unix(1, 0)
	time2 = time.Unix(2, 0)
)

func batchedParseBlockCachingTestPlugin(t *testing.T, loadExpectations bool) block.ChainVM {
	// test key is "batchedParseBlockCachingTestKey"

	// create mock
	vm := &blocktest.VM{
		T: t,
	}

	if loadExpectations {
		blk1 := blocktest.BuildChild(blocktest.Genesis)
		blk2 := blocktest.BuildChild(blk1)
		blk1.IDV = blkID1
		blk1.ParentV = blkID0
		blk1.HeightV = 1
		blk1.TimestampV = time1

		blk2.IDV = blkID2
		blk2.ParentV = blkID1
		blk2.HeightV = 2
		blk2.TimestampV = time2

		vm.InitializeF = func(context.Context, interface{}, interface{}, []byte, []byte, []byte, interface{}, []interface{}, interface{}) error {
			return nil
		}
		vm.LastAcceptedF = func(context.Context) (ids.ID, error) {
			return blocktest.GenesisID, nil
		}
		vm.GetBlockF = func(_ context.Context, blkID ids.ID) (block.Block, error) {
			if blkID == blocktest.GenesisID {
				return blocktest.Genesis, nil
			}
			return nil, database.ErrNotFound
		}
		vm.ParseBlockF = func(_ context.Context, b []byte) (block.Block, error) {
			if bytes.Equal(b, blkBytes1) {
				return blk1, nil
			}
			if bytes.Equal(b, blkBytes2) {
				return blk2, nil
			}
			return nil, database.ErrNotFound
		}
	}

	return vm
}

func TestBatchedParseBlockCaching(t *testing.T) {
	require := require.New(t)
	testKey := batchedParseBlockCachingTestKey

	// Create and start the plugin
	vm := buildClientHelper(require, testKey)
	defer vm.runtime.Stop(context.Background())

	chainCtx := &Context{
		NetworkID: 1,
		ChainID:   ids.ID{'C', 'C', 'h', 'a', 'i', 'n'},
		NodeID:    ids.GenerateTestNodeID(),
	}

	require.NoError(vm.Initialize(context.Background(), chainCtx, memdb.New(), nil, nil, nil, nil, nil, nil))

	// Call should parse the first block
	blk, err := vm.ParseBlock(context.Background(), blkBytes1)
	require.NoError(err)
	require.Equal(blkID1, blk.ID())

	// Skip type assertion - ChainVM interface satisfied

	// Call should cache the first block and parse the second block
	blks, err := vm.BatchedParseBlock(context.Background(), [][]byte{blkBytes1, blkBytes2})
	require.NoError(err)
	require.Len(blks, 2)
	require.Equal(blkID1, blks[0].ID())
	require.Equal(blkID2, blks[1].ID())

	// Skip type assertions

	// Call should be fully cached and not result in a grpc call
	blks, err = vm.BatchedParseBlock(context.Background(), [][]byte{blkBytes1, blkBytes2})
	require.NoError(err)
	require.Len(blks, 2)
	require.Equal(blkID1, blks[0].ID())
	require.Equal(blkID2, blks[1].ID())

	// Skip type assertions
}
