//go:build !grpc

// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"context"
	"net/http"
	"strings"
	"testing"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/version"
)

// nilBlockVM is a ChainVM whose block-producing calls violate the (block, error)
// contract by returning (nil, nil) — the behavior a real VM exhibits under heavy
// concurrent load ("no block to build right now" / a racing GetBlock miss). It
// exists to prove the ZAP VM-server never dereferences a nil Block (the recovered
// "panic in ZAP handler" that corrupts build/verify during a fresh-chain storm).
type nilBlockVM struct{}

func (nilBlockVM) Initialize(context.Context, block.Init) error            { return nil }
func (nilBlockVM) BuildBlock(context.Context) (block.Block, error)         { return nil, nil }
func (nilBlockVM) ParseBlock(context.Context, []byte) (block.Block, error) { return nil, nil }
func (nilBlockVM) GetBlock(context.Context, ids.ID) (block.Block, error)   { return nil, nil }
func (nilBlockVM) Shutdown(context.Context) error                          { return nil }
func (nilBlockVM) NewHTTPHandler(context.Context) (http.Handler, error)    { return nil, nil }
func (nilBlockVM) SetState(context.Context, uint32) error                  { return nil }
func (nilBlockVM) Version(context.Context) (string, error)                 { return "test", nil }
func (nilBlockVM) Connected(context.Context, ids.NodeID, *version.Application) error {
	return nil
}
func (nilBlockVM) Disconnected(context.Context, ids.NodeID) error { return nil }
func (nilBlockVM) HealthCheck(context.Context) (block.HealthCheckResult, error) {
	var r block.HealthCheckResult
	return r, nil
}
func (nilBlockVM) GetBlockIDAtHeight(context.Context, uint64) (ids.ID, error) {
	return ids.Empty, nil
}
func (nilBlockVM) SetPreference(context.Context, ids.ID) error   { return nil }
func (nilBlockVM) LastAccepted(context.Context) (ids.ID, error)  { return ids.Empty, nil }
func (nilBlockVM) WaitForEvent(context.Context) (block.Message, error) {
	var m block.Message
	return m, nil
}

var _ block.ChainVM = nilBlockVM{}

func encodeReq(t *testing.T, req interface{ Encode(*zapwire.Buffer) }) []byte {
	t.Helper()
	buf := zapwire.GetBuffer()
	req.Encode(buf)
	out := append([]byte(nil), buf.Bytes()...)
	zapwire.PutBuffer(buf)
	return out
}

// TestZAPHandler_NilBlockNoPanic drives every block-returning handler against a VM
// that returns (nil, nil) and asserts each returns a CLEAN error/response instead
// of dereferencing the nil block. The handler methods are called DIRECTLY (not via
// Handle, which recovers panics into errors) so a regression re-introducing the
// nil deref FAILS the test with a real panic rather than being masked.
func TestZAPHandler_NilBlockNoPanic(t *testing.T) {
	ctx := context.Background()
	s := newZAPVMServer(nilBlockVM{}, log.NoLog{})

	// BuildBlock: must NOT cache the nil block nor deref it; returns a BlockResponse
	// carrying a not-found error so consensus retries next tick.
	t.Run("BuildBlock", func(t *testing.T) {
		_, result, err := s.handleBuildBlock(ctx)
		if err != nil {
			t.Fatalf("handleBuildBlock returned transport error: %v", err)
		}
		resp := &zapwire.BlockResponse{}
		if derr := resp.Decode(zapwire.NewReader(result)); derr != nil {
			t.Fatalf("decode BlockResponse: %v", derr)
		}
		if resp.Err == zapwire.ErrorUnspecified {
			t.Fatalf("expected a not-found error in the response for a nil-built block, got Unspecified")
		}
		// The nil block must NOT have been cached.
		s.pendingBlockLock.Lock()
		cached := s.pendingBlock
		s.pendingBlockLock.Unlock()
		if cached != nil {
			t.Fatalf("nil block was cached in pendingBlock")
		}
	})

	t.Run("ParseBlock", func(t *testing.T) {
		payload := encodeReq(t, &zapwire.ParseBlockRequest{Bytes: []byte{1, 2, 3}})
		_, result, err := s.handleParseBlock(ctx, payload)
		if err != nil {
			t.Fatalf("handleParseBlock transport error: %v", err)
		}
		resp := &zapwire.BlockResponse{}
		if derr := resp.Decode(zapwire.NewReader(result)); derr != nil {
			t.Fatalf("decode BlockResponse: %v", derr)
		}
		if resp.Err == zapwire.ErrorUnspecified {
			t.Fatalf("expected a not-found error for a nil-parsed block, got Unspecified")
		}
	})

	t.Run("GetBlock", func(t *testing.T) {
		id := ids.GenerateTestID()
		payload := encodeReq(t, &zapwire.GetBlockRequest{ID: id[:]})
		_, result, err := s.handleGetBlock(ctx, payload)
		if err != nil {
			t.Fatalf("handleGetBlock transport error: %v", err)
		}
		resp := &zapwire.BlockResponse{}
		if derr := resp.Decode(zapwire.NewReader(result)); derr != nil {
			t.Fatalf("decode BlockResponse: %v", derr)
		}
		if resp.Err == zapwire.ErrorUnspecified {
			t.Fatalf("expected a not-found error for a nil GetBlock, got Unspecified")
		}
	})

	t.Run("BlockVerify", func(t *testing.T) {
		payload := encodeReq(t, &zapwire.BlockVerifyRequest{Bytes: []byte{1, 2, 3}})
		_, _, err := s.handleBlockVerify(ctx, payload)
		if err == nil {
			t.Fatalf("expected an error verifying a nil-parsed block")
		}
	})

	t.Run("BlockAccept", func(t *testing.T) {
		id := ids.GenerateTestID()
		payload := encodeReq(t, &zapwire.BlockAcceptRequest{ID: id[:]})
		_, _, err := s.handleBlockAccept(ctx, payload)
		if err == nil {
			t.Fatalf("expected an error accepting a nil block")
		}
	})

	t.Run("BlockReject", func(t *testing.T) {
		id := ids.GenerateTestID()
		payload := encodeReq(t, &zapwire.BlockRejectRequest{ID: id[:]})
		_, _, err := s.handleBlockReject(ctx, payload)
		if err == nil {
			t.Fatalf("expected an error rejecting a nil block")
		}
	})

	// Belt: through the recovering Handle dispatch, BuildBlock must return a clean
	// response whose transport error is NOT a recovered panic.
	t.Run("HandleDispatchNoRecoveredPanic", func(t *testing.T) {
		_, _, err := s.Handle(ctx, zapwire.MsgBuildBlock, nil)
		if err != nil && strings.Contains(err.Error(), "panic in handler") {
			t.Fatalf("ZAP Handle recovered a panic (nil deref not guarded): %v", err)
		}
	})
}
