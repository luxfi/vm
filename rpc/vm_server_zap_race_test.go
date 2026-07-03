//go:build !grpc

// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/version"
)

// racyVM reproduces the production data race that froze the Lux mainnet C-Chain
// at block 1082879. The ZAP transport dispatches every request in its own
// goroutine (api/zap transport.go handleConn), but the wrapped VM's block cache
// (vm/components/chain.State.verifiedBlocks) is a plain, unsynchronized map:
// ParseBlock READS it (State.getCachedBlock, state.go:216) while a concurrent
// BlockVerify WRITES it (block.go verifiedBlocks[id]=bw). Under a catch-up block
// storm a lagging validator issues many concurrent ParseBlock/Verify calls and
// the EVM subprocess dies with "fatal error: concurrent map read and map write".
//
// seen is that unsynchronized map. Any concurrency reaching it means the RPC
// server failed to honor the consensus engine's single-threaded VM-call
// contract. The fix is zapVMServer.vmCallLock, which serializes all
// state-touching handlers (WaitForEvent excluded — it is a long-poll).
type racyVM struct {
	seen map[ids.ID]struct{} // UNSYNCHRONIZED on purpose — the raced cache analog
}

func newRacyVM() *racyVM { return &racyVM{seen: make(map[ids.ID]struct{})} }

func blkIDFor(b []byte) ids.ID {
	var id ids.ID
	copy(id[:], b)
	return id
}

// ParseBlock mirrors State.getCachedBlock: it READS the shared map, then returns
// a block whose Verify WRITES it.
func (v *racyVM) ParseBlock(_ context.Context, b []byte) (block.Block, error) {
	id := blkIDFor(b)
	_, _ = v.seen[id] // map READ (races a concurrent Verify write without the lock)
	return &racyBlock{vm: v, id: id, bytes: b}, nil
}

func (v *racyVM) GetBlock(_ context.Context, id ids.ID) (block.Block, error) {
	_, _ = v.seen[id] // map READ
	return &racyBlock{vm: v, id: id}, nil
}

func (v *racyVM) Initialize(context.Context, block.Init) error         { return nil }
func (v *racyVM) BuildBlock(context.Context) (block.Block, error)      { return &racyBlock{vm: v}, nil }
func (v *racyVM) Shutdown(context.Context) error                       { return nil }
func (v *racyVM) NewHTTPHandler(context.Context) (http.Handler, error) { return nil, nil }
func (v *racyVM) SetState(context.Context, uint32) error               { return nil }
func (v *racyVM) Version(context.Context) (string, error)              { return "racy", nil }
func (v *racyVM) Connected(context.Context, ids.NodeID, *version.Application) error {
	return nil
}
func (v *racyVM) Disconnected(context.Context, ids.NodeID) error { return nil }
func (v *racyVM) HealthCheck(context.Context) (block.HealthCheckResult, error) {
	var r block.HealthCheckResult
	return r, nil
}
func (v *racyVM) GetBlockIDAtHeight(context.Context, uint64) (ids.ID, error) {
	return ids.Empty, nil
}
func (v *racyVM) SetPreference(context.Context, ids.ID) error  { return nil }
func (v *racyVM) LastAccepted(context.Context) (ids.ID, error) { return ids.Empty, nil }
func (v *racyVM) WaitForEvent(context.Context) (block.Message, error) {
	var m block.Message
	return m, nil
}

var _ block.ChainVM = (*racyVM)(nil)

type racyBlock struct {
	vm    *racyVM
	id    ids.ID
	bytes []byte
}

func (b *racyBlock) ID() ids.ID           { return b.id }
func (b *racyBlock) Parent() ids.ID       { return ids.Empty }
func (b *racyBlock) ParentID() ids.ID     { return ids.Empty }
func (b *racyBlock) Height() uint64       { return 1 }
func (b *racyBlock) Timestamp() time.Time { return time.Unix(0, 0) }
func (b *racyBlock) Status() uint8        { return 0 }
func (b *racyBlock) Bytes() []byte        { return b.bytes }
func (b *racyBlock) Verify(context.Context) error {
	b.vm.seen[b.id] = struct{}{} // map WRITE (races a concurrent ParseBlock read without the lock)
	return nil
}
func (b *racyBlock) Accept(context.Context) error { return nil }
func (b *racyBlock) Reject(context.Context) error { return nil }

var _ block.Block = (*racyBlock)(nil)

// TestZAPHandler_SerializesVMStateCalls is the permanent regression guard for the
// concurrent-map crash that froze mainnet C-Chain. It drives many concurrent
// ParseBlock (cache read) and BlockVerify (cache write) requests through
// zapVMServer.Handle. With vmCallLock the calls are serialized and the run is
// clean; if the lock is removed the run trips the -race detector ("concurrent
// map read and map write") and, even without -race, Go aborts with a hard
// "fatal error: concurrent map" — exactly the production failure mode. Run in
// CI under `go test -race`.
func TestZAPHandler_SerializesVMStateCalls(t *testing.T) {
	s := newZAPVMServer(newRacyVM(), log.NoLog{})
	ctx := context.Background()

	parsePayload := encodeReq(t, &zapwire.ParseBlockRequest{Bytes: []byte{1, 2, 3, 4}})
	verifyPayload := encodeReq(t, &zapwire.BlockVerifyRequest{Bytes: []byte{5, 6, 7, 8}})

	const (
		workers = 64
		iters   = 200
	)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				// Interleave cache reads (ParseBlock) and cache writes
				// (BlockVerify) so an unserialized dispatch races.
				if (i+j)%2 == 0 {
					_, _, _ = s.Handle(ctx, zapwire.MsgParseBlock, parsePayload)
				} else {
					_, _, _ = s.Handle(ctx, zapwire.MsgBlockVerify, verifyPayload)
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestZAPHandler_WaitForEventStaysConcurrent proves the fix does not serialize
// WaitForEvent: many WaitForEvent calls (the long-poll deliberately excluded
// from vmCallLock) must run concurrently while state calls proceed, so a slow
// or blocked WaitForEvent can never wedge block production. This regression
// guards against a "fix" that over-locks and reintroduces the head-of-line
// blocking the transport's per-request dispatch was built to avoid.
func TestZAPHandler_WaitForEventStaysConcurrent(t *testing.T) {
	s := newZAPVMServer(newRacyVM(), log.NoLog{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A WaitForEvent that blocks until ctx is cancelled must not hold vmCallLock,
	// else the concurrent ParseBlock below would deadlock and time out.
	blockingVM := &blockingWaitVM{racyVM: newRacyVM(), release: make(chan struct{})}
	sb := newZAPVMServer(blockingVM, log.NoLog{})

	done := make(chan struct{})
	go func() {
		_, _, _ = sb.Handle(ctx, zapwire.MsgWaitForEvent, nil)
		close(done)
	}()

	// This state call must complete even while WaitForEvent is in flight.
	parsePayload := encodeReq(t, &zapwire.ParseBlockRequest{Bytes: []byte{9}})
	got := make(chan struct{})
	go func() {
		_, _, _ = s.Handle(ctx, zapwire.MsgParseBlock, parsePayload)
		_, _, _ = sb.Handle(ctx, zapwire.MsgParseBlock, parsePayload)
		close(got)
	}()

	select {
	case <-got:
		// ParseBlock completed while WaitForEvent was blocked — correct.
	case <-time.After(5 * time.Second):
		t.Fatal("ParseBlock blocked behind an in-flight WaitForEvent: vmCallLock must exclude WaitForEvent")
	}

	close(blockingVM.release)
	<-done
}

// blockingWaitVM blocks in WaitForEvent until release is closed.
type blockingWaitVM struct {
	*racyVM
	release chan struct{}
}

func (v *blockingWaitVM) WaitForEvent(ctx context.Context) (block.Message, error) {
	select {
	case <-v.release:
	case <-ctx.Done():
	}
	var m block.Message
	return m, nil
}
