//go:build !grpc

// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"context"
	"errors"
	"testing"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/log"
)

// quasarCapableVM is a ChainVM that ALSO implements the export capability
// (SetLastQuasarFinalized/LastQuasarHeight) — the shape of the C-Chain EVM's
// concrete *VM. It embeds nilBlockVM for the generic ChainVM surface (defined in
// vm_server_zap_nilblock_test.go, same package) and records the pushed height.
type quasarCapableVM struct {
	nilBlockVM
	height uint64
}

func (v *quasarCapableVM) SetLastQuasarFinalized(h uint64) { v.height = h }
func (v *quasarCapableVM) LastQuasarHeight() uint64        { return v.height }

// TestVMCapabilities_QuasarExportAdvertisedOnlyWhenImplemented is the SERVER half
// of the cross-process export bridge (the deploy-blocking gap: the export tier was
// dormant across the rpcchainvm plugin boundary because no capability crossed it).
// The bit the node reads from the Initialize handshake (InitializeResponse.Capabilities,
// set from vmCapabilities) must be present IFF the wrapped VM implements the export
// methods — so an export-capable plugin (C-Chain EVM) is wired and a generic plugin
// stays Nova-only.
func TestVMCapabilities_QuasarExportAdvertisedOnlyWhenImplemented(t *testing.T) {
	if got := vmCapabilities(&quasarCapableVM{}); got&zapwire.CapQuasarExport == 0 {
		t.Fatalf("export-capable VM must advertise CapQuasarExport, got caps=%d", got)
	}
	if got := vmCapabilities(nilBlockVM{}); got&zapwire.CapQuasarExport != 0 {
		t.Fatalf("generic VM must NOT advertise CapQuasarExport, got caps=%d", got)
	}
}

// TestQuasarHandlers_ReachVMAndGateOnCapability drives the two Quasar handlers on
// the REAL server against a capable VM (they reach the VM and round-trip the height
// through the wire encoding) and against a generic VM (they refuse with the typed
// unsupported error — defense-in-depth, since the node never sends them to a VM that
// did not advertise the capability). The capable path goes through Handle (dispatch +
// vmCallLock + panic-recovery), exactly as production; the refusal path calls the
// handlers directly so the exact sentinel is asserted, not a recovered wrapper.
func TestQuasarHandlers_ReachVMAndGateOnCapability(t *testing.T) {
	ctx := context.Background()

	q := &quasarCapableVM{}
	s := newZAPVMServer(q, log.NoLog{})

	// SetLastQuasarFinalized crosses the dispatch into the VM.
	if _, _, err := s.Handle(ctx, zapwire.MsgSetQuasarFinalized, encodeReq(t, &zapwire.SetQuasarFinalizedRequest{Height: 77})); err != nil {
		t.Fatalf("handle MsgSetQuasarFinalized: %v", err)
	}
	if q.LastQuasarHeight() != 77 {
		t.Fatalf("set did not reach the VM: got %d want 77", q.LastQuasarHeight())
	}

	// QuasarHeight reads it back out through the wire response encoding.
	_, out, err := s.Handle(ctx, zapwire.MsgQuasarHeight, nil)
	if err != nil {
		t.Fatalf("handle MsgQuasarHeight: %v", err)
	}
	resp := &zapwire.QuasarHeightResponse{}
	if derr := resp.Decode(zapwire.NewReader(out)); derr != nil {
		t.Fatalf("decode QuasarHeightResponse: %v", derr)
	}
	if resp.Height != 77 {
		t.Fatalf("quasar-height round-trip: got %d want 77", resp.Height)
	}

	// A generic VM refuses both with the typed unsupported error.
	sg := newZAPVMServer(nilBlockVM{}, log.NoLog{})
	if _, _, gerr := sg.handleQuasarHeight(); !errors.Is(gerr, errQuasarUnsupported) {
		t.Fatalf("generic VM handleQuasarHeight: want errQuasarUnsupported, got %v", gerr)
	}
	if _, _, gerr := sg.handleSetQuasarFinalized(encodeReq(t, &zapwire.SetQuasarFinalizedRequest{Height: 1})); !errors.Is(gerr, errQuasarUnsupported) {
		t.Fatalf("generic VM handleSetQuasarFinalized: want errQuasarUnsupported, got %v", gerr)
	}
}
