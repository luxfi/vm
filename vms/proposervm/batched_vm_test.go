// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package proposervm

import (
	"bytes"
	"context"
	"crypto"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/database/prefixdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/metric"
	"github.com/luxfi/staking"
	"github.com/luxfi/upgrade"
	"github.com/luxfi/vm/utils/timer/mockable"

	"github.com/luxfi/consensus"
	"github.com/luxfi/consensus/core/interfaces"
	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/consensus/engine/chain/chaintest"
	consensustest "github.com/luxfi/consensus/test/helpers"
	validators "github.com/luxfi/consensus/validator"
	validatorstest "github.com/luxfi/consensus/validator/validatorstest"
	"github.com/luxfi/vm/chain/blocktest"

	blockbuilder "github.com/luxfi/vm/vms/proposervm/block"
)

// validatorStateAdapter adapts validatorstest.State to consensus ValidatorState interface
type validatorStateAdapter struct {
	state *validatorstest.State
}

func (v *validatorStateAdapter) GetChainID(chainID ids.ID) (ids.ID, error) {
	// Not available in test state, return empty ID
	return ids.Empty, nil
}

func (v *validatorStateAdapter) GetNetID(chainID ids.ID) (ids.ID, error) {
	// Not available in test state, return empty ID
	return ids.Empty, nil
}

func (v *validatorStateAdapter) GetValidatorSet(ctx context.Context, height uint64, netID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	// Use the test state's GetValidatorSet directly
	return v.state.GetValidatorSet(ctx, height, netID)
}

func (v *validatorStateAdapter) GetCurrentHeight(ctx context.Context) (uint64, error) {
	return v.state.GetCurrentHeight(ctx)
}

func (v *validatorStateAdapter) GetMinimumHeight(ctx context.Context) (uint64, error) {
	// Not available in test state, return 0
	return 0, nil
}

func (v *validatorStateAdapter) GetCurrentValidators(ctx context.Context, height uint64, netID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	// Use the test state's GetValidatorSet to get current validators
	return v.state.GetValidatorSet(ctx, height, netID)
}

func (v *validatorStateAdapter) GetWarpValidatorSets(ctx context.Context, heights []uint64, netIDs []ids.ID) (map[ids.ID]map[uint64]*validators.WarpSet, error) {
	// Not needed for basic proposervm tests, return empty
	return make(map[ids.ID]map[uint64]*validators.WarpSet), nil
}

func (v *validatorStateAdapter) GetWarpValidatorSet(ctx context.Context, height uint64, netID ids.ID) (*validators.WarpSet, error) {
	// Not needed for basic proposervm tests, return empty WarpSet
	return &validators.WarpSet{}, nil
}

func TestCoreVMNotRemote(t *testing.T) {
	// if coreVM is not remote VM, a specific error is returned
	require := require.New(t)
	var (
		activationTime = time.Unix(0, 0)
		durangoTime    = activationTime
	)
	_, _, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	blkID := ids.Empty
	maxBlocksNum := 1000               // a high value to get all built blocks
	maxBlocksSize := 1000000           // a high value to get all built blocks
	maxBlocksRetrivalTime := time.Hour // a high value to get all built blocks
	_, err := proVM.GetAncestors(
		context.Background(),
		blkID,
		maxBlocksNum,
		maxBlocksSize,
		maxBlocksRetrivalTime,
	)
	require.ErrorIs(err, block.ErrRemoteVMNotImplemented)

	var blks [][]byte
	shouldBeEmpty, err := proVM.BatchedParseBlock(context.Background(), blks)
	require.NoError(err)
	require.Empty(shouldBeEmpty)
}

func TestGetAncestorsPreForkOnly(t *testing.T) {
	require := require.New(t)
	var (
		activationTime = mockable.MaxTime
		durangoTime    = activationTime
	)
	coreVM, proRemoteVM := initTestRemoteProposerVM(t, activationTime, durangoTime)
	defer func() {
		require.NoError(proRemoteVM.Shutdown(context.Background()))
	}()

	// Build some prefork blocks....
	coreBlk1 := blocktest.BuildChild(blocktest.Genesis)
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk1, nil
	}
	builtBlk1, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)

	// prepare build of next block
	require.NoError(proRemoteVM.SetPreference(context.Background(), builtBlk1.ID()))
	coreVM.VM.GetBlockF = func(_ context.Context, blkID ids.ID) (block.Block, error) {
		switch blkID {
		case coreBlk1.ID():
			return coreBlk1, nil
		default:
			return nil, errUnknownBlock
		}
	}

	coreBlk2 := blocktest.BuildChild(coreBlk1)
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk2, nil
	}
	builtBlk2, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)

	// prepare build of next block
	require.NoError(proRemoteVM.SetPreference(context.Background(), builtBlk2.ID()))
	coreVM.VM.GetBlockF = func(_ context.Context, blkID ids.ID) (block.Block, error) {
		switch blkID {
		case coreBlk2.ID():
			return coreBlk2, nil
		default:
			return nil, errUnknownBlock
		}
	}

	coreBlk3 := blocktest.BuildChild(coreBlk2)
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk3, nil
	}
	builtBlk3, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)

	// ...Call GetAncestors on them ...
	// Note: we assumed that if blkID is not known, that's NOT an error.
	// Simply return an empty result
	coreVM.GetAncestorsF = func(_ context.Context, blkID ids.ID, _ int, _ int, _ time.Duration) ([][]byte, error) {
		res := make([][]byte, 0, 3)
		switch blkID {
		case coreBlk3.ID():
			res = append(res, coreBlk3.Bytes())
			res = append(res, coreBlk2.Bytes())
			res = append(res, coreBlk1.Bytes())
			return res, nil
		case coreBlk2.ID():
			res = append(res, coreBlk2.Bytes())
			res = append(res, coreBlk1.Bytes())
			return res, nil
		case coreBlk1.ID():
			res = append(res, coreBlk1.Bytes())
			return res, nil
		default:
			return res, nil
		}
	}

	reqBlkID := builtBlk3.ID()
	maxBlocksNum := 1000               // a high value to get all built blocks
	maxBlocksSize := 1000000           // a high value to get all built blocks
	maxBlocksRetrivalTime := time.Hour // a high value to get all built blocks
	res, err := proRemoteVM.GetAncestors(
		context.Background(),
		reqBlkID,
		maxBlocksNum,
		maxBlocksSize,
		maxBlocksRetrivalTime,
	)

	// ... and check returned values are as expected
	require.NoError(err)
	require.Len(res, 3)
	require.Equal(builtBlk3.Bytes(), res[0])
	require.Equal(builtBlk2.Bytes(), res[1])
	require.Equal(builtBlk1.Bytes(), res[2])

	// another good call
	reqBlkID = builtBlk1.ID()
	res, err = proRemoteVM.GetAncestors(
		context.Background(),
		reqBlkID,
		maxBlocksNum,
		maxBlocksSize,
		maxBlocksRetrivalTime,
	)
	require.NoError(err)
	require.Len(res, 1)
	require.Equal(builtBlk1.Bytes(), res[0])

	// a faulty call
	reqBlkID = ids.Empty
	res, err = proRemoteVM.GetAncestors(
		context.Background(),
		reqBlkID,
		maxBlocksNum,
		maxBlocksSize,
		maxBlocksRetrivalTime,
	)
	require.NoError(err)
	require.Empty(res)
}

func TestGetAncestorsPostForkOnly(t *testing.T) {
	require := require.New(t)
	var (
		activationTime = time.Unix(0, 0)
		durangoTime    = activationTime
	)
	coreVM, proRemoteVM := initTestRemoteProposerVM(t, activationTime, durangoTime)
	defer func() {
		require.NoError(proRemoteVM.Shutdown(context.Background()))
	}()

	// Build some post-Fork blocks....
	coreBlk1 := blocktest.BuildChild(blocktest.Genesis)
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk1, nil
	}
	builtBlk1, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)

	// prepare build of next block
	require.NoError(builtBlk1.Verify(context.Background()))
	require.NoError(proRemoteVM.SetPreference(context.Background(), builtBlk1.ID()))
	require.NoError(waitForProposerWindow(proRemoteVM, builtBlk1.(*postForkBlock).innerBlk, 0))

	coreBlk2 := blocktest.BuildChild(coreBlk1)
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk2, nil
	}
	builtBlk2, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)

	// prepare build of next block
	require.NoError(builtBlk2.Verify(context.Background()))
	require.NoError(proRemoteVM.SetPreference(context.Background(), builtBlk2.ID()))
	require.NoError(waitForProposerWindow(proRemoteVM, builtBlk2.(*postForkBlock).innerBlk, 0))

	coreBlk3 := blocktest.BuildChild(coreBlk2)
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk3, nil
	}
	builtBlk3, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)

	require.NoError(builtBlk3.Verify(context.Background()))
	require.NoError(proRemoteVM.SetPreference(context.Background(), builtBlk3.ID()))

	// ...Call GetAncestors on them ...
	// Note: we assumed that if blkID is not known, that's NOT an error.
	// Simply return an empty result
	coreVM.GetAncestorsF = func(_ context.Context, blkID ids.ID, _ int, _ int, _ time.Duration) ([][]byte, error) {
		res := make([][]byte, 0, 3)
		switch blkID {
		case coreBlk3.ID():
			res = append(res, coreBlk3.Bytes())
			res = append(res, coreBlk2.Bytes())
			res = append(res, coreBlk1.Bytes())
			return res, nil
		case coreBlk2.ID():
			res = append(res, coreBlk2.Bytes())
			res = append(res, coreBlk1.Bytes())
			return res, nil
		case coreBlk1.ID():
			res = append(res, coreBlk1.Bytes())
			return res, nil
		default:
			return res, nil
		}
	}

	coreVM.VM.ParseBlockF = func(_ context.Context, b []byte) (block.Block, error) {
		switch {
		case bytes.Equal(b, blocktest.GenesisBytes):
			return blocktest.Genesis, nil
		case bytes.Equal(b, coreBlk1.Bytes()):
			return coreBlk1, nil
		case bytes.Equal(b, coreBlk2.Bytes()):
			return coreBlk2, nil
		case bytes.Equal(b, coreBlk3.Bytes()):
			return coreBlk3, nil
		default:
			return nil, errUnknownBlock
		}
	}

	reqBlkID := builtBlk3.ID()
	maxBlocksNum := 1000               // a high value to get all built blocks
	maxBlocksSize := 1000000           // a high value to get all built blocks
	maxBlocksRetrivalTime := time.Hour // a high value to get all built blocks
	res, err := proRemoteVM.GetAncestors(
		context.Background(),
		reqBlkID,
		maxBlocksNum,
		maxBlocksSize,
		maxBlocksRetrivalTime,
	)

	// ... and check returned values are as expected
	require.NoError(err)
	require.Len(res, 3)
	require.Equal(builtBlk3.Bytes(), res[0])
	require.Equal(builtBlk2.Bytes(), res[1])
	require.Equal(builtBlk1.Bytes(), res[2])

	// another good call
	reqBlkID = builtBlk1.ID()
	res, err = proRemoteVM.GetAncestors(
		context.Background(),
		reqBlkID,
		maxBlocksNum,
		maxBlocksSize,
		maxBlocksRetrivalTime,
	)
	require.NoError(err)
	require.Len(res, 1)
	require.Equal(builtBlk1.Bytes(), res[0])

	// a faulty call
	reqBlkID = ids.Empty
	res, err = proRemoteVM.GetAncestors(
		context.Background(),
		reqBlkID,
		maxBlocksNum,
		maxBlocksSize,
		maxBlocksRetrivalTime,
	)
	require.NoError(err)
	require.Empty(res)
}

func TestGetAncestorsAtSnomanPlusPlusFork(t *testing.T) {
	require := require.New(t)

	var (
		currentTime  = time.Now().Truncate(time.Second)
		preForkTime  = currentTime.Add(5 * time.Minute)
		forkTime     = currentTime.Add(10 * time.Minute)
		postForkTime = currentTime.Add(15 * time.Minute)

		durangoTime = forkTime
	)

	// enable ProBlks in next future
	coreVM, proRemoteVM := initTestRemoteProposerVM(t, forkTime, durangoTime)
	defer func() {
		require.NoError(proRemoteVM.Shutdown(context.Background()))
	}()

	// Build some prefork blocks....
	proRemoteVM.Set(preForkTime)
	coreBlk1 := blocktest.BuildChild(blocktest.Genesis)
	coreBlk1.TimestampV = preForkTime
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk1, nil
	}
	builtBlk1, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)
	require.IsType(&preForkBlock{}, builtBlk1)

	// prepare build of next block
	require.NoError(proRemoteVM.SetPreference(context.Background(), builtBlk1.ID()))
	coreVM.VM.GetBlockF = func(_ context.Context, blkID ids.ID) (block.Block, error) {
		switch {
		case blkID == coreBlk1.ID():
			return coreBlk1, nil
		default:
			return nil, errUnknownBlock
		}
	}

	coreBlk2 := blocktest.BuildChild(coreBlk1)
	coreBlk2.TimestampV = postForkTime
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk2, nil
	}
	builtBlk2, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)
	require.IsType(&preForkBlock{}, builtBlk2)

	// prepare build of next block
	require.NoError(proRemoteVM.SetPreference(context.Background(), builtBlk2.ID()))
	coreVM.VM.GetBlockF = func(_ context.Context, blkID ids.ID) (block.Block, error) {
		switch {
		case blkID == coreBlk2.ID():
			return coreBlk2, nil
		default:
			return nil, errUnknownBlock
		}
	}

	// .. and some post-fork
	proRemoteVM.Set(postForkTime)
	coreBlk3 := blocktest.BuildChild(coreBlk2)
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk3, nil
	}
	builtBlk3, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)
	require.IsType(&postForkBlock{}, builtBlk3)

	// prepare build of next block
	require.NoError(builtBlk3.Verify(context.Background()))
	require.NoError(proRemoteVM.SetPreference(context.Background(), builtBlk3.ID()))
	require.NoError(waitForProposerWindow(proRemoteVM, builtBlk3.(*postForkBlock).innerBlk, builtBlk3.(*postForkBlock).PChainHeight()))

	coreBlk4 := blocktest.BuildChild(coreBlk3)
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk4, nil
	}
	builtBlk4, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)
	require.IsType(&postForkBlock{}, builtBlk4)
	require.NoError(builtBlk4.Verify(context.Background()))

	// ...Call GetAncestors on them ...
	// Note: we assumed that if blkID is not known, that's NOT an error.
	// Simply return an empty result
	coreVM.GetAncestorsF = func(_ context.Context, blkID ids.ID, maxBlocksNum int, _ int, _ time.Duration) ([][]byte, error) {
		sortedBlocks := [][]byte{
			coreBlk4.Bytes(),
			coreBlk3.Bytes(),
			coreBlk2.Bytes(),
			coreBlk1.Bytes(),
		}
		var startIndex int
		switch blkID {
		case coreBlk4.ID():
			startIndex = 0
		case coreBlk3.ID():
			startIndex = 1
		case coreBlk2.ID():
			startIndex = 2
		case coreBlk1.ID():
			startIndex = 3
		default:
			return nil, nil // unknown blockID
		}

		endIndex := min(startIndex+maxBlocksNum, len(sortedBlocks))
		return sortedBlocks[startIndex:endIndex], nil
	}

	// load all known blocks
	reqBlkID := builtBlk4.ID()
	maxBlocksNum := 1000                      // an high value to get all built blocks
	maxBlocksSize := 1000000                  // an high value to get all built blocks
	maxBlocksRetrivalTime := 10 * time.Minute // an high value to get all built blocks
	res, err := proRemoteVM.GetAncestors(
		context.Background(),
		reqBlkID,
		maxBlocksNum,
		maxBlocksSize,
		maxBlocksRetrivalTime,
	)

	// ... and check returned values are as expected
	require.NoError(err)
	require.Len(res, 4)
	require.Equal(builtBlk4.Bytes(), res[0])
	require.Equal(builtBlk3.Bytes(), res[1])
	require.Equal(builtBlk2.Bytes(), res[2])
	require.Equal(builtBlk1.Bytes(), res[3])

	// Regression case: load some prefork and some postfork blocks.
	reqBlkID = builtBlk4.ID()
	maxBlocksNum = 3
	res, err = proRemoteVM.GetAncestors(
		context.Background(),
		reqBlkID,
		maxBlocksNum,
		maxBlocksSize,
		maxBlocksRetrivalTime,
	)

	// ... and check returned values are as expected
	require.NoError(err)
	require.Len(res, 3)
	require.Equal(builtBlk4.Bytes(), res[0])
	require.Equal(builtBlk3.Bytes(), res[1])
	require.Equal(builtBlk2.Bytes(), res[2])

	// another good call
	reqBlkID = builtBlk1.ID()
	res, err = proRemoteVM.GetAncestors(
		context.Background(),
		reqBlkID,
		maxBlocksNum,
		maxBlocksSize,
		maxBlocksRetrivalTime,
	)
	require.NoError(err)
	require.Len(res, 1)
	require.Equal(builtBlk1.Bytes(), res[0])

	// a faulty call
	reqBlkID = ids.Empty
	res, err = proRemoteVM.GetAncestors(
		context.Background(),
		reqBlkID,
		maxBlocksNum,
		maxBlocksSize,
		maxBlocksRetrivalTime,
	)
	require.NoError(err)
	require.Empty(res)
}

func TestBatchedParseBlockPreForkOnly(t *testing.T) {
	require := require.New(t)
	var (
		activationTime = mockable.MaxTime
		durangoTime    = activationTime
	)
	coreVM, proRemoteVM := initTestRemoteProposerVM(t, activationTime, durangoTime)
	defer func() {
		require.NoError(proRemoteVM.Shutdown(context.Background()))
	}()

	// Build some prefork blocks....
	coreBlk1 := blocktest.BuildChild(blocktest.Genesis)
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk1, nil
	}
	builtBlk1, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)

	// prepare build of next block
	require.NoError(proRemoteVM.SetPreference(context.Background(), builtBlk1.ID()))
	coreVM.VM.GetBlockF = func(_ context.Context, blkID ids.ID) (block.Block, error) {
		switch blkID {
		case coreBlk1.ID():
			return coreBlk1, nil
		default:
			return nil, errUnknownBlock
		}
	}

	coreBlk2 := blocktest.BuildChild(coreBlk1)
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk2, nil
	}
	builtBlk2, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)

	// prepare build of next block
	require.NoError(proRemoteVM.SetPreference(context.Background(), builtBlk2.ID()))
	coreVM.VM.GetBlockF = func(_ context.Context, blkID ids.ID) (block.Block, error) {
		switch {
		case blkID == coreBlk2.ID():
			return coreBlk2, nil
		default:
			return nil, errUnknownBlock
		}
	}

	coreBlk3 := blocktest.BuildChild(coreBlk2)
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk3, nil
	}
	builtBlk3, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)

	coreVM.VM.ParseBlockF = func(_ context.Context, b []byte) (block.Block, error) {
		switch {
		case bytes.Equal(b, coreBlk1.Bytes()):
			return coreBlk1, nil
		case bytes.Equal(b, coreBlk2.Bytes()):
			return coreBlk2, nil
		case bytes.Equal(b, coreBlk3.Bytes()):
			return coreBlk3, nil
		default:
			return nil, errUnknownBlock
		}
	}

	coreVM.BatchedParseBlockF = func(_ context.Context, blks [][]byte) ([]block.Block, error) {
		res := make([]block.Block, 0, len(blks))
		for _, blkBytes := range blks {
			switch {
			case bytes.Equal(blkBytes, coreBlk1.Bytes()):
				res = append(res, coreBlk1)
			case bytes.Equal(blkBytes, coreBlk2.Bytes()):
				res = append(res, coreBlk2)
			case bytes.Equal(blkBytes, coreBlk3.Bytes()):
				res = append(res, coreBlk3)
			default:
				return nil, errUnknownBlock
			}
		}
		return res, nil
	}

	bytesToParse := [][]byte{
		builtBlk1.Bytes(),
		builtBlk2.Bytes(),
		builtBlk3.Bytes(),
	}
	res, err := proRemoteVM.BatchedParseBlock(context.Background(), bytesToParse)
	require.NoError(err)
	require.Len(res, 3)
	require.Equal(builtBlk1.ID(), res[0].ID())
	require.Equal(builtBlk2.ID(), res[1].ID())
	require.Equal(builtBlk3.ID(), res[2].ID())
}

func TestBatchedParseBlockParallel(t *testing.T) {
	parentID := ids.ID{1}
	timestamp := time.Unix(123, 0)
	pChainHeight := uint64(2)
	chainID := ids.GenerateTestID()

	testVM := &TestRemoteProposerVM{
		VM: &blocktest.VM{
			ParseBlockF: func(_ context.Context, rawBlock []byte) (block.Block, error) {
				return &chaintest.TestBlock{BytesV: rawBlock}, nil
			},
		},
		BatchedVM: &blocktest.BatchedVM{
			BatchedParseBlockF: func(_ context.Context, rawBlocks [][]byte) ([]block.Block, error) {
				blocks := make([]block.Block, len(rawBlocks))
				for i, rawBlock := range rawBlocks {
					blocks[i] = &chaintest.TestBlock{BytesV: rawBlock}
				}
				return blocks, nil
			},
		},
	}

	vm := VM{
		ctx:       &consensus.Context{ChainID: chainID},
		ChainVM:   testVM,
		batchedVM: testVM,
	}

	tlsCert, err := staking.NewTLSCert()
	require.NoError(t, err)

	cert, err := staking.ParseCertificate(tlsCert.Leaf.Raw)
	require.NoError(t, err)
	key := tlsCert.PrivateKey.(crypto.Signer)

	blockThatCantBeParsed := chaintest.BuildChild(chaintest.Genesis)

	blocksWithUnparsable := makeParseableBlocks(t, parentID, timestamp, pChainHeight, cert, chainID, key)
	blocksWithUnparsable[50] = blockThatCantBeParsed.Bytes()

	parsableBlocks := makeParseableBlocks(t, parentID, timestamp, pChainHeight, cert, chainID, key)

	for _, testCase := range []struct {
		name         string
		preForkIndex int
		rawBlocks    [][]byte
	}{
		{
			name:      "empty input",
			rawBlocks: [][]byte{},
		},
		{
			name:         "pre-fork is somewhere in the middle",
			rawBlocks:    blocksWithUnparsable,
			preForkIndex: 50,
		},
		{
			name:         "all blocks are post fork",
			rawBlocks:    parsableBlocks,
			preForkIndex: len(parsableBlocks),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			require := require.New(t)
			blocks, err := vm.BatchedParseBlock(context.Background(), testCase.rawBlocks)
			require.NoError(err)

			returnedBlockBytes := make([][]byte, len(blocks))
			for i, block := range blocks {
				returnedBlockBytes[i] = block.Bytes()
			}
			require.Equal(testCase.rawBlocks, returnedBlockBytes)

			for i, block := range blocks {
				// BatchedParseBlock returns blockAdapter wrapping the actual blocks
				adapter, ok := block.(*blockAdapter)
				require.True(ok, "block should be wrapped in blockAdapter")
				// When statelessblock parsing fails at index preForkIndex,
				// all blocks from that index onwards are treated as pre-fork
				if i >= testCase.preForkIndex {
					require.IsType(&preForkBlock{}, adapter.Block)
				} else {
					require.IsType(&postForkBlock{}, adapter.Block)
				}
			}
		})
	}
}

func makeParseableBlocks(t *testing.T, parentID ids.ID, timestamp time.Time, pChainHeight uint64, cert *staking.Certificate, chainID ids.ID, key crypto.Signer) [][]byte {
	makeSignedBlock := func(i int) []byte {
		buff := binary.AppendVarint(nil, int64(i))

		signedBlock, err := blockbuilder.Build(
			parentID,
			timestamp,
			pChainHeight,
			blockbuilder.Epoch{},
			cert,
			buff,
			chainID,
			key,
		)
		require.NoError(t, err)

		return signedBlock.Bytes()
	}

	blockBytes := make([][]byte, 100)
	for i := range blockBytes {
		blockBytes[i] = makeSignedBlock(i)
	}
	return blockBytes
}

func TestBatchedParseBlockPostForkOnly(t *testing.T) {
	require := require.New(t)
	var (
		activationTime = time.Unix(0, 0)
		durangoTime    = activationTime
	)
	coreVM, proRemoteVM := initTestRemoteProposerVM(t, activationTime, durangoTime)
	defer func() {
		require.NoError(proRemoteVM.Shutdown(context.Background()))
	}()

	// Build some post-Fork blocks....
	coreBlk1 := blocktest.BuildChild(blocktest.Genesis)
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk1, nil
	}
	builtBlk1, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)

	// prepare build of next block
	require.NoError(builtBlk1.Verify(context.Background()))
	require.NoError(proRemoteVM.SetPreference(context.Background(), builtBlk1.ID()))
	require.NoError(waitForProposerWindow(proRemoteVM, builtBlk1.(*postForkBlock).innerBlk, 0))

	coreBlk2 := blocktest.BuildChild(coreBlk1)
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk2, nil
	}
	builtBlk2, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)

	// prepare build of next block
	require.NoError(builtBlk2.Verify(context.Background()))
	require.NoError(proRemoteVM.SetPreference(context.Background(), builtBlk2.ID()))
	require.NoError(waitForProposerWindow(proRemoteVM, builtBlk2.(*postForkBlock).innerBlk, builtBlk2.(*postForkBlock).PChainHeight()))

	coreBlk3 := blocktest.BuildChild(coreBlk2)
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk3, nil
	}
	builtBlk3, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)

	coreVM.VM.ParseBlockF = func(_ context.Context, b []byte) (block.Block, error) {
		switch {
		case bytes.Equal(b, coreBlk1.Bytes()):
			return coreBlk1, nil
		case bytes.Equal(b, coreBlk2.Bytes()):
			return coreBlk2, nil
		case bytes.Equal(b, coreBlk3.Bytes()):
			return coreBlk3, nil
		default:
			return nil, errUnknownBlock
		}
	}

	coreVM.BatchedParseBlockF = func(_ context.Context, blks [][]byte) ([]block.Block, error) {
		res := make([]block.Block, 0, len(blks))
		for _, blkBytes := range blks {
			switch {
			case bytes.Equal(blkBytes, coreBlk1.Bytes()):
				res = append(res, coreBlk1)
			case bytes.Equal(blkBytes, coreBlk2.Bytes()):
				res = append(res, coreBlk2)
			case bytes.Equal(blkBytes, coreBlk3.Bytes()):
				res = append(res, coreBlk3)
			default:
				return nil, errUnknownBlock
			}
		}
		return res, nil
	}

	bytesToParse := [][]byte{
		builtBlk1.Bytes(),
		builtBlk2.Bytes(),
		builtBlk3.Bytes(),
	}
	res, err := proRemoteVM.BatchedParseBlock(context.Background(), bytesToParse)
	require.NoError(err)
	require.Len(res, 3)
	require.Equal(builtBlk1.ID(), res[0].ID())
	require.Equal(builtBlk2.ID(), res[1].ID())
	require.Equal(builtBlk3.ID(), res[2].ID())
}

func TestBatchedParseBlockAtSnomanPlusPlusFork(t *testing.T) {
	require := require.New(t)

	var (
		currentTime  = time.Now().Truncate(time.Second)
		preForkTime  = currentTime.Add(5 * time.Minute)
		forkTime     = currentTime.Add(10 * time.Minute)
		postForkTime = currentTime.Add(15 * time.Minute)

		durangoTime = forkTime
	)

	// enable ProBlks in next future
	coreVM, proRemoteVM := initTestRemoteProposerVM(t, forkTime, durangoTime)
	defer func() {
		require.NoError(proRemoteVM.Shutdown(context.Background()))
	}()

	// Build some prefork blocks....
	proRemoteVM.Set(preForkTime)
	coreBlk1 := blocktest.BuildChild(blocktest.Genesis)
	coreBlk1.TimestampV = preForkTime
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk1, nil
	}
	builtBlk1, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)
	require.IsType(&preForkBlock{}, builtBlk1)

	// prepare build of next block
	require.NoError(proRemoteVM.SetPreference(context.Background(), builtBlk1.ID()))
	coreVM.VM.GetBlockF = func(_ context.Context, blkID ids.ID) (block.Block, error) {
		switch {
		case blkID == coreBlk1.ID():
			return coreBlk1, nil
		default:
			return nil, errUnknownBlock
		}
	}

	coreBlk2 := blocktest.BuildChild(coreBlk1)
	coreBlk2.TimestampV = postForkTime
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk2, nil
	}
	builtBlk2, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)
	require.IsType(&preForkBlock{}, builtBlk2)

	// prepare build of next block
	require.NoError(proRemoteVM.SetPreference(context.Background(), builtBlk2.ID()))
	coreVM.VM.GetBlockF = func(_ context.Context, blkID ids.ID) (block.Block, error) {
		switch {
		case blkID == coreBlk2.ID():
			return coreBlk2, nil
		default:
			return nil, errUnknownBlock
		}
	}

	// .. and some post-fork
	proRemoteVM.Set(postForkTime)
	coreBlk3 := blocktest.BuildChild(coreBlk2)
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk3, nil
	}
	builtBlk3, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)
	require.IsType(&postForkBlock{}, builtBlk3)

	// prepare build of next block
	require.NoError(builtBlk3.Verify(context.Background()))
	require.NoError(proRemoteVM.SetPreference(context.Background(), builtBlk3.ID()))
	require.NoError(waitForProposerWindow(proRemoteVM, builtBlk3.(*postForkBlock).innerBlk, builtBlk3.(*postForkBlock).PChainHeight()))

	coreBlk4 := blocktest.BuildChild(coreBlk3)
	coreVM.VM.BuildBlockF = func(context.Context) (block.Block, error) {
		return coreBlk4, nil
	}
	builtBlk4, err := proRemoteVM.BuildBlock(context.Background())
	require.NoError(err)
	require.IsType(&postForkBlock{}, builtBlk4)
	require.NoError(builtBlk4.Verify(context.Background()))

	coreVM.VM.ParseBlockF = func(_ context.Context, b []byte) (block.Block, error) {
		switch {
		case bytes.Equal(b, coreBlk1.Bytes()):
			return coreBlk1, nil
		case bytes.Equal(b, coreBlk2.Bytes()):
			return coreBlk2, nil
		case bytes.Equal(b, coreBlk3.Bytes()):
			return coreBlk3, nil
		case bytes.Equal(b, coreBlk4.Bytes()):
			return coreBlk4, nil
		default:
			return nil, errUnknownBlock
		}
	}

	coreVM.BatchedParseBlockF = func(_ context.Context, blks [][]byte) ([]block.Block, error) {
		res := make([]block.Block, 0, len(blks))
		for _, blkBytes := range blks {
			switch {
			case bytes.Equal(blkBytes, coreBlk1.Bytes()):
				res = append(res, coreBlk1)
			case bytes.Equal(blkBytes, coreBlk2.Bytes()):
				res = append(res, coreBlk2)
			case bytes.Equal(blkBytes, coreBlk3.Bytes()):
				res = append(res, coreBlk3)
			case bytes.Equal(blkBytes, coreBlk4.Bytes()):
				res = append(res, coreBlk4)
			default:
				return nil, errUnknownBlock
			}
		}
		return res, nil
	}

	bytesToParse := [][]byte{
		builtBlk4.Bytes(),
		builtBlk3.Bytes(),
		builtBlk2.Bytes(),
		builtBlk1.Bytes(),
	}

	res, err := proRemoteVM.BatchedParseBlock(context.Background(), bytesToParse)
	require.NoError(err)
	require.Len(res, 4)
	require.Equal(builtBlk4.ID(), res[0].ID())
	require.Equal(builtBlk3.ID(), res[1].ID())
	require.Equal(builtBlk2.ID(), res[2].ID())
	require.Equal(builtBlk1.ID(), res[3].ID())
}

type TestRemoteProposerVM struct {
	*blocktest.VM
	*blocktest.BatchedVM
}

// GetBlockIDAtHeight resolves ambiguous selector by delegating to VM
func (vm *TestRemoteProposerVM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	return vm.VM.GetBlockIDAtHeight(ctx, height)
}

// testWindower is a test implementation of the Windower interface that always
// allows the configured nodeID to propose immediately
type testWindower struct {
	nodeID ids.NodeID
}

func (w *testWindower) Proposers(ctx context.Context, blockHeight, pChainHeight uint64, maxWindows int) ([]ids.NodeID, error) {
	// Return the nodeID as the first proposer
	proposers := make([]ids.NodeID, 1, maxWindows)
	proposers[0] = w.nodeID
	return proposers, nil
}

func (w *testWindower) Delay(ctx context.Context, blockHeight, pChainHeight uint64, validatorID ids.NodeID, maxWindows int) (time.Duration, error) {
	// If it's our nodeID, no delay needed
	if validatorID == w.nodeID {
		return 0, nil
	}
	// Otherwise, return a small delay
	return 5 * time.Second, nil
}

func (w *testWindower) ExpectedProposer(ctx context.Context, blockHeight, pChainHeight, slot uint64) (ids.NodeID, error) {
	// Always return our nodeID as the expected proposer
	return w.nodeID, nil
}

func (w *testWindower) MinDelayForProposer(ctx context.Context, blockHeight, pChainHeight uint64, nodeID ids.NodeID, startSlot uint64) (time.Duration, error) {
	// If it's our nodeID, no delay needed
	if nodeID == w.nodeID {
		return 0, nil
	}
	// Otherwise, return a small delay
	return 5 * time.Second, nil
}

// GetAncestors delegates to BatchedVM
func (vm *TestRemoteProposerVM) GetAncestors(ctx context.Context, blkID ids.ID, maxBlocksNum int, maxBlocksSize int, maxBlocksRetrievalTime time.Duration) ([][]byte, error) {
	return vm.BatchedVM.GetAncestors(ctx, blkID, maxBlocksNum, maxBlocksSize, maxBlocksRetrievalTime)
}

// BatchedParseBlock delegates to BatchedVM
func (vm *TestRemoteProposerVM) BatchedParseBlock(ctx context.Context, blks [][]byte) ([]block.Block, error) {
	return vm.BatchedVM.BatchedParseBlock(ctx, blks)
}

func initTestRemoteProposerVM(
	t *testing.T,
	activationTime,
	durangoTime time.Time,
) (
	*TestRemoteProposerVM,
	*VM,
) {
	require := require.New(t)

	initialState := []byte("genesis state")
	coreVM := TestRemoteProposerVM{
		VM:        &blocktest.VM{},
		BatchedVM: &blocktest.BatchedVM{},
	}
	coreVM.VM.T = t
	coreVM.BatchedVM.T = t

	coreVM.VM.InitializeF = func(
		context.Context,
		interface{},
		interface{},
		[]byte,
		[]byte,
		[]byte,
		interface{},
		[]interface{},
		interface{},
	) error {
		return nil
	}
	coreVM.LastAcceptedF = func(_ context.Context) (ids.ID, error) {
		return blocktest.GenesisID, nil
	}
	coreVM.GetBlockF = func(_ context.Context, blkID ids.ID) (block.Block, error) {
		switch blkID {
		case blocktest.GenesisID:
			return blocktest.Genesis, nil
		default:
			return nil, errUnknownBlock
		}
	}
	coreVM.VM.ParseBlockF = func(_ context.Context, b []byte) (block.Block, error) {
		switch {
		case bytes.Equal(b, blocktest.GenesisBytes):
			return blocktest.Genesis, nil
		default:
			return nil, errUnknownBlock
		}
	}

	proVM := New(
		&coreVM,
		Config{
			Upgrades: upgrade.Config{
				ApricotPhase4Time:            activationTime,
				ApricotPhase4MinPChainHeight: 0,
				DurangoTime:                  durangoTime,
			},
			MinBlkDelay:         DefaultMinBlockDelay,
			NumHistoricalBlocks: DefaultNumHistoricalBlocks,
			StakingLeafSigner:   pTestSigner,
			StakingCertLeaf:     pTestCert,
			Registerer:          metric.NewNoOp().Registry(),
		},
	)

	valState := validatorstest.NewTestState()
	valState.GetCurrentHeightF = func(context.Context) (uint64, error) {
		return defaultPChainHeight, nil
	}

	ctx := consensustest.Context(t, consensustest.CChainID)
	nodeID := ids.NodeIDFromCert(&ids.Certificate{
		Raw:       pTestCert.Raw,
		PublicKey: pTestCert.PublicKey,
	})
	ctx.NodeID = nodeID

	// Create adapter for consensus ValidatorState interface
	ctx.ValidatorState = &validatorStateAdapter{state: valState}

	// Store NodeID in validator state for use in tests
	thisNodeID := nodeID

	// Set valState.GetValidatorSetF to use captured nodeID
	valState.GetValidatorSetF = func(ctx context.Context, height uint64, netID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
		var (
			nodeID1 = ids.BuildTestNodeID([]byte{1})
			nodeID2 = ids.BuildTestNodeID([]byte{2})
			nodeID3 = ids.BuildTestNodeID([]byte{3})
		)
		return map[ids.NodeID]*validators.GetValidatorOutput{
			thisNodeID: {
				NodeID: thisNodeID,
				Light:  10,
				Weight: 10,
			},
			nodeID1: {
				NodeID: nodeID1,
				Light:  5,
				Weight: 5,
			},
			nodeID2: {
				NodeID: nodeID2,
				Light:  6,
				Weight: 6,
			},
			nodeID3: {
				NodeID: nodeID3,
				Light:  7,
				Weight: 7,
			},
		}, nil
	}

	require.NoError(proVM.Initialize(
		context.Background(),
		ctx,
		prefixdb.New([]byte{}, memdb.New()), // make sure that DBs are compressed correctly
		initialState,
		nil,
		nil,
		nil,
		[]interface{}{},
		nil,
	))

	// Initialize shouldn't be called again
	coreVM.VM.InitializeF = nil

	// Replace the windower with a test windower that allows immediate block building
	proVM.Windower = &testWindower{
		nodeID: thisNodeID,
	}

	// Set the clock to activation time to avoid "time too far advanced" errors
	proVM.Clock.Set(activationTime)

	require.NoError(proVM.SetState(context.Background(), uint32(interfaces.Ready)))
	require.NoError(proVM.SetPreference(context.Background(), blocktest.GenesisID))
	return &coreVM, proVM
}
