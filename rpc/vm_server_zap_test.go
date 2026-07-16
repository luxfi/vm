//go:build !grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"context"
	"testing"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/log"
	"github.com/luxfi/vm/chain"
)

// baseVM embeds chain.ChainVM so it satisfies the full generic contract with no
// boilerplate. The probe + Quasar handlers under test never invoke the embedded
// (nil) methods, so leaving them unimplemented is safe for these unit tests.
type baseVM struct{ chain.ChainVM }

// quasarVMStub is a ChainVM that ALSO implements the OPTIONAL quasarExporter
// surface the server probes for at construction.
type quasarVMStub struct {
	baseVM
	finalized uint64
	height    uint64
}

func (q *quasarVMStub) SetLastQuasarFinalized(h uint64) { q.finalized = h }
func (q *quasarVMStub) LastQuasarHeight() uint64        { return q.height }

// Compile-time contracts: both stubs are ChainVMs; only the quasar stub is a
// quasarExporter (so the server's probe distinguishes them).
var (
	_ chain.ChainVM  = baseVM{}
	_ chain.ChainVM  = (*quasarVMStub)(nil)
	_ quasarExporter = (*quasarVMStub)(nil)
)

func TestCapabilitiesProbe(t *testing.T) {
	logger := log.NewTestLogger(log.DebugLevel)

	// Generic VM: no optional add-ons → Capabilities 0 → node stays Nova-only.
	if got := newZAPVMServer(baseVM{}, logger).capabilities(); got != 0 {
		t.Fatalf("generic VM must advertise 0 capabilities, got %d", got)
	}

	// Quasar-capable VM: probe hits → CapQuasarExport advertised.
	if got := newZAPVMServer(&quasarVMStub{}, logger).capabilities(); got != zapwire.CapQuasarExport {
		t.Fatalf("quasar VM must advertise CapQuasarExport (%d), got %d", zapwire.CapQuasarExport, got)
	}
}

func TestQuasarHandlersRoundTrip(t *testing.T) {
	logger := log.NewTestLogger(log.DebugLevel)
	stub := &quasarVMStub{height: 99}
	s := newZAPVMServer(stub, logger)
	ctx := context.Background()

	// MsgSetQuasarFinalized forwards the height into the wrapped VM.
	req := &zapwire.SetQuasarFinalizedRequest{Height: 42}
	buf := zapwire.GetBuffer()
	req.Encode(buf)
	payload := append([]byte(nil), buf.Bytes()...)
	zapwire.PutBuffer(buf)

	mt, resp, err := s.handleSetQuasarFinalized(ctx, payload)
	if err != nil {
		t.Fatalf("handleSetQuasarFinalized: %v", err)
	}
	if mt != zapwire.MsgSetQuasarFinalized || resp != nil {
		t.Fatalf("set-quasar-finalized reply: mt=%d resp=%v", mt, resp)
	}
	if stub.finalized != 42 {
		t.Fatalf("SetLastQuasarFinalized not applied: got %d want 42", stub.finalized)
	}

	// MsgQuasarHeight returns the wrapped VM's clamped height.
	mt, resp, err = s.handleQuasarHeight(ctx)
	if err != nil {
		t.Fatalf("handleQuasarHeight: %v", err)
	}
	if mt != zapwire.MsgQuasarHeight {
		t.Fatalf("quasar-height reply type: got %d", mt)
	}
	var hr zapwire.QuasarHeightResponse
	if err := hr.Decode(zapwire.NewReader(resp)); err != nil {
		t.Fatalf("decode QuasarHeightResponse: %v", err)
	}
	if hr.Height != 99 {
		t.Fatalf("quasar height: got %d want 99", hr.Height)
	}
}

// TestQuasarHandlersRefusedWhenUnsupported: a stray Quasar message on a generic
// VM is refused with an error, not silently dropped or a nil-pointer panic.
func TestQuasarHandlersRefusedWhenUnsupported(t *testing.T) {
	s := newZAPVMServer(baseVM{}, log.NewTestLogger(log.DebugLevel))
	if _, _, err := s.handleQuasarHeight(context.Background()); err == nil {
		t.Fatal("handleQuasarHeight on a non-quasar VM must error")
	}
	if _, _, err := s.handleSetQuasarFinalized(context.Background(), nil); err == nil {
		t.Fatal("handleSetQuasarFinalized on a non-quasar VM must error")
	}
}
