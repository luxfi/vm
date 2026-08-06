// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package atomiczap_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/database/prefixdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/chains/atomic"
	"github.com/luxfi/vm/chains/atomic/atomiczap"
)

// seam stands up the real thing: one atomic.Memory, two per-chain handles out of
// it, a ZAP server over the "C" handle, and a client dialing it over a real
// loopback socket. Nothing here is a mock — the point of these tests is that a
// plugin talking through this transport observes exactly what an in-process VM
// observes off its Runtime.
type seam struct {
	cChainID ids.ID
	dChainID ids.ID
	smC      atomic.SharedMemory // C's handle, served over ZAP
	smD      atomic.SharedMemory // D's handle, used in-process to publish
	client   *atomiczap.Client   // what a plugin-hosted C-Chain would hold
}

func newSeam(t *testing.T) *seam {
	t.Helper()

	cChainID := ids.GenerateTestID()
	dChainID := ids.GenerateTestID()

	m := atomic.NewMemory(prefixdb.New([]byte{0}, memdb.New()))
	smC := m.NewSharedMemory(cChainID)
	smD := m.NewSharedMemory(dChainID)

	addr, stop, err := atomiczap.Serve(smC)
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	t.Cleanup(stop)
	if addr == "" {
		t.Fatal("serve returned an empty addr for a non-nil handle")
	}

	client, err := atomiczap.Dial(context.Background(), addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return &seam{cChainID: cChainID, dChainID: dChainID, smC: smC, smD: smD, client: client}
}

// publishDtoC has D write an object for C, the way the dexvm's executeExport
// does at block accept.
func (s *seam) publishDtoC(t *testing.T, key ids.ID, value []byte, traits ...[]byte) {
	t.Helper()
	if err := s.smD.Apply(map[ids.ID]*atomic.Requests{
		s.cChainID: {PutRequests: []*atomic.Element{{
			Key:    key[:],
			Value:  value,
			Traits: traits,
		}}},
	}); err != nil {
		t.Fatalf("publish D->C: %v", err)
	}
}

// settlementObject is the 69-byte C<->D seam wire:
// rail(1) | owner(20) | asset(32) | amount(8) | spent(8).
func settlementObject(rail byte, owner byte, amount uint64) []byte {
	obj := make([]byte, 69)
	obj[0] = rail
	for i := 1; i < 21; i++ {
		obj[i] = owner
	}
	for i := 21; i < 53; i++ {
		obj[i] = 0xA0
	}
	for i := 0; i < 8; i++ {
		obj[60-i] = byte(amount >> (8 * i))
	}
	return obj
}

// TestRemoteGet_SeesWhatTheNodeWrote is the core claim: an object D publishes
// into the node's shared memory is readable, byte for byte, by a client on the
// far side of the process boundary. This is the read the DEX Phase-B settlement
// makes, and its absence is why every swap reverted.
func TestRemoteGet_SeesWhatTheNodeWrote(t *testing.T) {
	s := newSeam(t)

	key := ids.GenerateTestID()
	want := settlementObject(0 /*railSwap*/, 0x11, 90)
	s.publishDtoC(t, key, want)

	// The in-process handle sees it...
	local, err := s.smC.Get(s.dChainID, [][]byte{key[:]})
	if err != nil {
		t.Fatalf("local get: %v", err)
	}
	if !bytes.Equal(local[0], want) {
		t.Fatal("in-process handle did not return the published object")
	}

	// ...and so must the remote one, identically.
	remote, err := s.client.Get(s.dChainID, [][]byte{key[:]})
	if err != nil {
		t.Fatalf("remote get: %v", err)
	}
	if len(remote) != 1 {
		t.Fatalf("remote get returned %d values, want 1", len(remote))
	}
	if !bytes.Equal(remote[0], want) {
		t.Fatalf("remote get = %x, want %x", remote[0], want)
	}
}

// TestRemoteGet_AbsentKeyErrorsLikeInProcess pins the real contract rather than
// the one the interface comment suggests. atomic.sharedMemory.Get resolves each
// key through the value database and returns (nil, err) on the FIRST miss, so a
// Get naming any absent key fails as a whole. Reproducing that faithfully across
// the boundary matters: softening a miss into an empty value would let a caller
// that checks only err conclude an object exists when it does not — and on this
// seam that caller is the one deciding whether to credit a balance.
func TestRemoteGet_AbsentKeyErrorsLikeInProcess(t *testing.T) {
	s := newSeam(t)

	present := ids.GenerateTestID()
	absent := ids.GenerateTestID()
	s.publishDtoC(t, present, settlementObject(0, 0x22, 7))

	// In process: an absent key errors.
	if _, err := s.smC.Get(s.dChainID, [][]byte{absent[:]}); err == nil {
		t.Fatal("in-process Get on an absent key returned nil error — contract changed")
	}
	// Remote must do the same.
	if _, err := s.client.Get(s.dChainID, [][]byte{absent[:]}); err == nil {
		t.Fatal("remote Get on an absent key returned nil error")
	}
	// And a batch containing an absent key must fail as a whole, not partially.
	if _, err := s.client.Get(s.dChainID, [][]byte{present[:], absent[:]}); err == nil {
		t.Fatal("remote Get returned nil error for a batch containing an absent key")
	}
}

// TestRemoteGet_MultiKeyAlignment: on the success path every key gets its own
// value at its own index. A slide here would bind a settlement credit to another
// object's owner/asset/amount.
func TestRemoteGet_MultiKeyAlignment(t *testing.T) {
	s := newSeam(t)

	k1, k2, k3 := ids.GenerateTestID(), ids.GenerateTestID(), ids.GenerateTestID()
	v1 := settlementObject(0, 0x11, 1)
	v2 := settlementObject(1, 0x22, 2)
	v3 := settlementObject(0, 0x33, 3)
	s.publishDtoC(t, k1, v1)
	s.publishDtoC(t, k2, v2)
	s.publishDtoC(t, k3, v3)

	values, err := s.client.Get(s.dChainID, [][]byte{k3[:], k1[:], k2[:]})
	if err != nil {
		t.Fatalf("remote get: %v", err)
	}
	if len(values) != 3 {
		t.Fatalf("got %d values for 3 keys", len(values))
	}
	for i, want := range [][]byte{v3, v1, v2} {
		if !bytes.Equal(values[i], want) {
			t.Fatalf("value[%d] = %x, want %x — values slid off their keys", i, values[i], want)
		}
	}
}

// TestRemoteApply_MutatesTheNodesMemory is the write half: what a plugin applies
// at block accept must land in the node's real shared memory, visible to the
// peer chain in process. This is the C->D Phase-A export.
func TestRemoteApply_MutatesTheNodesMemory(t *testing.T) {
	s := newSeam(t)

	key := ids.GenerateTestID()
	obj := settlementObject(0, 0x33, 100)
	owner := bytes.Repeat([]byte{0x33}, 20)

	if err := s.client.Apply(map[ids.ID]*atomic.Requests{
		s.dChainID: {PutRequests: []*atomic.Element{{
			Key:    key[:],
			Value:  obj,
			Traits: [][]byte{owner},
		}}},
	}); err != nil {
		t.Fatalf("remote apply: %v", err)
	}

	// D, in process, must now see it.
	got, err := s.smD.Get(s.cChainID, [][]byte{key[:]})
	if err != nil {
		t.Fatalf("peer get: %v", err)
	}
	if !bytes.Equal(got[0], obj) {
		t.Fatalf("peer sees %x, want %x — the plugin's export did not reach shared memory", got[0], obj)
	}
}

// TestRemoteApply_RemoveConsumesExactlyOnce covers the consume leg and the
// idempotence the no-batch design depends on: replaying the same window must be
// a no-op, not an error, because the flush is at-least-once by construction.
func TestRemoteApply_RemoveConsumesExactlyOnce(t *testing.T) {
	s := newSeam(t)

	key := ids.GenerateTestID()
	s.publishDtoC(t, key, settlementObject(0, 0x44, 5))

	remove := map[ids.ID]*atomic.Requests{
		s.dChainID: {RemoveRequests: [][]byte{key[:]}},
	}
	if err := s.client.Apply(remove); err != nil {
		t.Fatalf("remote apply remove: %v", err)
	}

	// A consumed object is gone: Get on it now errors, exactly as in process.
	if _, err := s.client.Get(s.dChainID, [][]byte{key[:]}); err == nil {
		t.Fatal("object still readable after remove — consume did not take effect")
	}

	// Replay the identical window. At-least-once delivery is the contract, so a
	// second apply of an already-applied remove must not fail; if it did, a
	// crash between Apply and the flushed-seq marker advance would wedge the
	// chain on restart (the failure mode the in-process code paid for with a
	// batch).
	if err := s.client.Apply(remove); err != nil {
		t.Fatalf("replayed remove must be a no-op, got: %v", err)
	}
}

// TestRemoteIndexed_EnumeratesByTrait covers the call the D-Chain's autonomous
// seam drive is built on. It walks pending C->D intents by a fixed discovery
// trait and recovers each key from the LastKey cursor, because a shared-memory
// value does not carry its own key. Without this the drive finds nothing and no
// intent is ever imported — so a transport that omitted Indexed would leave the
// seam just as dark as no transport at all.
func TestRemoteIndexed_EnumeratesByTrait(t *testing.T) {
	s := newSeam(t)

	// The real discovery trait: sha256 of the domain string the D-Chain uses.
	pending := sha256.Sum256([]byte("lux.dex.native.intent.pending.v1"))
	trait := pending[:]

	key := ids.GenerateTestID()
	owner := bytes.Repeat([]byte{0x55}, 20)
	s.publishDtoC(t, key, settlementObject(0, 0x55, 42), owner, trait)

	// Also publish an object WITHOUT the discovery trait; it must not surface.
	other := ids.GenerateTestID()
	s.publishDtoC(t, other, settlementObject(0, 0x66, 1), bytes.Repeat([]byte{0x66}, 20))

	_, _, lastKey, err := s.client.Indexed(s.dChainID, [][]byte{trait}, trait, nil, 1)
	if err != nil {
		t.Fatalf("remote indexed: %v", err)
	}
	if len(lastKey) != 32 {
		t.Fatalf("lastKey len = %d, want 32 — the drive recovers keys from this cursor", len(lastKey))
	}
	if !bytes.Equal(lastKey, key[:]) {
		t.Fatalf("lastKey = %x, want the trait-tagged key %x", lastKey, key[:])
	}
}

// TestRemoteApply_RefusesBatch: a batch is a live handle on a database the
// caller's process does not own. Refusing is the honest answer; silently
// dropping it would let a caller believe the state commit and the shared-memory
// mutation were one write when they are not.
func TestRemoteApply_RefusesBatch(t *testing.T) {
	s := newSeam(t)

	err := s.client.Apply(
		map[ids.ID]*atomic.Requests{s.dChainID: {RemoveRequests: [][]byte{{0x01}}}},
		memdb.New().NewBatch(),
	)
	if !errors.Is(err, atomiczap.ErrBatchUnsupported) {
		t.Fatalf("err = %v, want ErrBatchUnsupported", err)
	}
}

// TestServe_NilHandleYieldsNoServer: when the node wired no shared memory the
// plugin must be told so, not handed a server over a nil handle. An empty addr
// is what makes the plugin leave its own handle nil and revert fail-closed
// rather than dereference nil inside block execution.
func TestServe_NilHandleYieldsNoServer(t *testing.T) {
	addr, stop, err := atomiczap.Serve(nil)
	if err != nil {
		t.Fatalf("serve(nil): %v", err)
	}
	defer stop()
	if addr != "" {
		t.Fatalf("addr = %q, want empty for a nil handle", addr)
	}
}

// TestRemoteApply_EmptyIsNoOp: a block with no cross-chain ops must not make a
// call at all, and must not error.
func TestRemoteApply_EmptyIsNoOp(t *testing.T) {
	s := newSeam(t)
	if err := s.client.Apply(nil); err != nil {
		t.Fatalf("empty apply: %v", err)
	}
	if err := s.client.Apply(map[ids.ID]*atomic.Requests{}); err != nil {
		t.Fatalf("empty apply: %v", err)
	}
}
