// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// state_race_test.go — the unsynchronised block-cache maps.
//
// State was written against an upstream contract that the consensus engine holds the chain
// lock across every VM call, so exactly one VM call runs at a time. The ZAP VM server does
// NOT reinstate that contract — it dispatches ParseBlock/GetBlock and the
// Verify/Accept/Reject wrappers concurrently. `verifiedBlocks` (a plain map) and
// `lastAcceptedBlock` (a pointer field) are the only State that is not self-synchronising;
// every cache.Cacher field carries its own mutex.
//
// A Go map fatal is UNRECOVERABLE: it kills the plugin process outright. luxd itself keeps
// running and keeps answering info.getNodeVersion while its chain is gone — pod-Ready and
// /v1/health both stay green — and there is NO self-heal.
//
// The fix gives State the lock for exactly those two fields, never held across a call into
// the inner VM. Run under `-race`.
package chain

import (
	"context"
	"sync"
	"testing"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	block "github.com/luxfi/vm/chain"
	"github.com/luxfi/vm/chain/blocktest"
)

// TestState_ConcurrentParseAndVerifyAccept drives the exact call mix the ZAP server
// produces: gossip ParseBlock/GetBlock readers racing the Verify → Accept writer.
//
// Under `go test -race` this reports a data race on verifiedBlocks / lastAcceptedBlock
// before the fix; in production, without -race, it is the "concurrent map read and map
// write" fatal that killed the plugin. Clean after.
func TestState_ConcurrentParseAndVerifyAccept(t *testing.T) {
	ctx := context.Background()

	const chainLen = 64
	testBlks := NewTestBlocks(chainLen)
	genesisBlock := testBlks[0]
	genesisBlock.StatusV = blocktest.Accepted
	for _, b := range testBlks[1:] {
		b.StatusV = blocktest.Processing
	}

	// Read-only lookup maps built up front. The shared createInternalBlockFuncs helpers
	// MUTATE their maps inside parseBlk, which would report a race in the TEST harness and
	// mask the ones under test; these closures only read.
	byID := make(map[ids.ID]block.Block, len(testBlks))
	byBytes := make(map[string]block.Block, len(testBlks))
	for _, b := range testBlks {
		byID[b.ID()] = b
		byBytes[string(b.Bytes())] = b
	}
	getBlock := func(_ context.Context, id ids.ID) (block.Block, error) {
		if b, ok := byID[id]; ok {
			return b, nil
		}
		return nil, database.ErrNotFound
	}
	parseBlock := func(_ context.Context, b []byte) (block.Block, error) {
		if blk, ok := byBytes[string(b)]; ok {
			return blk, nil
		}
		return nil, database.ErrNotFound
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

	var wg sync.WaitGroup

	// WRITER — the consensus path: Verify then Accept up the chain. Verify writes
	// verifiedBlocks; Accept deletes from it AND swings lastAcceptedBlock.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, b := range testBlks[1:] {
			wrapped, err := chainState.GetBlock(ctx, b.ID())
			if err != nil {
				continue
			}
			if err := wrapped.Verify(ctx); err != nil {
				continue
			}
			_ = wrapped.Accept(ctx)
		}
	}()

	// READERS — the ZAP RPC handlers: ParseBlock/GetBlock/IsProcessing/LastAccepted, all
	// reading those same two fields with no chain lock held.
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, b := range testBlks {
				_, _ = chainState.ParseBlock(ctx, b.Bytes())
				_, _ = chainState.GetBlock(ctx, b.ID())
				_ = chainState.IsProcessing(b.ID())
				_, _ = chainState.LastAccepted(ctx)
			}
		}()
	}

	wg.Wait()
}
