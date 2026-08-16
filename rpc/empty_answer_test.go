// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"context"
	"errors"
	"testing"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/vm/chain"
)

// emptyVM answers every block-returning call the way the contract forbids: no
// block, and no reason either. The server is on the far side of a process
// boundary from whatever plugin it is serving, so this is input, not a
// hypothetical.
type emptyVM struct{ baseVM }

func (emptyVM) BuildBlock(context.Context) (chain.Block, error)        { return nil, nil }
func (emptyVM) ParseBlock(context.Context, []byte) (chain.Block, error) { return nil, nil }
func (emptyVM) GetBlock(context.Context, ids.ID) (chain.Block, error)   { return nil, nil }

// failingVM answers with a reason the wire has no code for.
type failingVM struct{ baseVM }

var errPlainOldFailure = errors.New("no pending transactions")

func (failingVM) BuildBlock(context.Context) (chain.Block, error) {
	return nil, errPlainOldFailure
}

func decodeBlock(t *testing.T, payload []byte) zapwire.BlockResponse {
	t.Helper()
	resp := zapwire.BlockResponse{}
	if err := resp.Decode(zapwire.NewReader(payload)); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	return resp
}

// The handlers are called directly rather than through Handle, which recovers.
// A dereference has to reach the test as a panic, not as a logged line.
func TestEmptyAnswerIsRefused(t *testing.T) {
	s := newZAPVMServer(emptyVM{}, log.NewTestLogger(log.DebugLevel))
	ctx := context.Background()
	id := ids.GenerateTestID()

	build := func() []byte {
		_, payload, err := s.handleBuildBlock(ctx)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		return payload
	}

	for name, payload := range map[string][]byte{
		"build": build(),
	} {
		if got := decodeBlock(t, payload).Err; got == zapwire.ErrorUnspecified {
			t.Fatalf("%s: an empty answer reported success", name)
		}
	}

	// An empty answer must not be remembered: the next caller would be handed
	// the same nil back off the cache, forever.
	if s.pendingBlock != nil {
		t.Fatal("an empty answer was cached")
	}

	req := &zapwire.GetBlockRequest{ID: id[:]}
	buf := zapwire.GetBuffer()
	req.Encode(buf)
	if _, payload, err := s.handleGetBlock(ctx, buf.Bytes()); err != nil {
		t.Fatalf("get: %v", err)
	} else if decodeBlock(t, payload).Err == zapwire.ErrorUnspecified {
		t.Fatal("get: an empty answer reported success")
	}
	zapwire.PutBuffer(buf)
}

// Whatever the VM failed for, the reply must not carry the code that means it
// worked — a caller reading Err would take the zero-valued block as real.
func TestUnnamedFailureIsNotReportedAsSuccess(t *testing.T) {
	s := newZAPVMServer(failingVM{}, log.NewTestLogger(log.DebugLevel))
	_, payload, err := s.handleBuildBlock(context.Background())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := decodeBlock(t, payload).Err; got != zapwire.ErrorInternal {
		t.Fatalf("Err = %v, want ErrorInternal", got)
	}
}
