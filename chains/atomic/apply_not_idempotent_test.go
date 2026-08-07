// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package atomic

import (
	"testing"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
)

// apply_not_idempotent_test.go pins a property that callers have twice assumed the
// other way, and that decides how every cross-process caller must order its writes.
//
// Apply is NOT idempotent. A caller that cannot share a database batch with shared
// memory (any out-of-process plugin — the C-Chain EVM, the D-Chain) therefore cannot
// choose "apply first, advance the marker after, a replay is a no-op". A replay is
// not a no-op. It is either a hard error that is fatal on an accept path, or — worse
// — a silent re-creation of value the peer already consumed.
//
// These tests exist so the next person to reach for at-least-once delivery here has
// to delete a passing test to do it.

func testMemory(t *testing.T) (*Memory, ids.ID, ids.ID) {
	t.Helper()
	m := NewMemory(memdb.New())
	return m, ids.ID{0xCC}, ids.ID{0xDD}
}

// TestApplyDuplicatePutIsAnError proves a replayed Put of a still-unconsumed object
// ERRORS. On a block-accept path that error is fatal, i.e. the chain halts.
func TestApplyDuplicatePutIsAnError(t *testing.T) {
	m, cChain, dChain := testMemory(t)
	c := m.NewSharedMemory(cChain)

	key := []byte("object-key")
	put := map[ids.ID]*Requests{
		dChain: {PutRequests: []*Element{{Key: key, Value: []byte("value"), Traits: [][]byte{{0x01}}}}},
	}

	if err := c.Apply(put); err != nil {
		t.Fatalf("first Apply must succeed: %v", err)
	}
	// Rebuild the request: Apply mutates the map's peerChainID bookkeeping.
	put2 := map[ids.ID]*Requests{
		dChain: {PutRequests: []*Element{{Key: key, Value: []byte("value"), Traits: [][]byte{{0x01}}}}},
	}
	err := c.Apply(put2)
	if err == nil {
		t.Fatal("a REPLAYED Put returned no error — if this is ever true, revisit every " +
			"caller that was told replay is unsafe")
	}
	t.Logf("replayed Put correctly errored: %v", err)
}

// TestApplyReplayedPutAfterConsumeRecreatesTheObject is the dangerous one. Once the
// peer has consumed an object, its key is deleted outright — so a replayed Put no
// longer collides and instead RE-CREATES the object, handing the peer the same value
// a second time. This is why "apply first, then commit" is not merely fragile but
// unsound for a value-bearing seam.
func TestApplyReplayedPutAfterConsumeRecreatesTheObject(t *testing.T) {
	m, cChain, dChain := testMemory(t)
	c := m.NewSharedMemory(cChain)
	d := m.NewSharedMemory(dChain)

	key := []byte("object-key")
	value := []byte("100 units")
	mkPut := func() map[ids.ID]*Requests {
		return map[ids.ID]*Requests{
			dChain: {PutRequests: []*Element{{Key: key, Value: value, Traits: [][]byte{{0x01}}}}},
		}
	}

	// C exports the object; D sees it.
	if err := c.Apply(mkPut()); err != nil {
		t.Fatalf("export failed: %v", err)
	}
	vals, err := d.Get(cChain, [][]byte{key})
	if err != nil || len(vals) != 1 || string(vals[0]) != string(value) {
		t.Fatalf("D should see the exported object, got %v (err %v)", vals, err)
	}

	// D consumes it.
	if err := d.Apply(map[ids.ID]*Requests{cChain: {RemoveRequests: [][]byte{key}}}); err != nil {
		t.Fatalf("consume failed: %v", err)
	}
	if _, err := d.Get(cChain, [][]byte{key}); err == nil {
		t.Fatal("the object should be gone after D consumed it")
	}

	// C crashes before advancing its flushed marker and REPLAYS the same window.
	if err := c.Apply(mkPut()); err != nil {
		t.Fatalf("the replay did not even error, and: %v", err)
	}
	vals, err = d.Get(cChain, [][]byte{key})
	if err == nil && len(vals) == 1 && string(vals[0]) == string(value) {
		t.Logf("CONFIRMED: a replayed Put re-created a consumed object — the peer can be " +
			"funded twice. At-least-once delivery is unsound for this seam.")
		return
	}
	t.Fatalf("expected the replayed Put to re-create the object (the hazard this test "+
		"documents); got vals=%v err=%v", vals, err)
}

// TestApplyRemoveReplayDependsOnWhatWasThere pins the Remove leg's behaviour
// precisely, because it is NOT uniform and the difference is easy to get wrong.
//
//   - Replaying the Remove of an object that WAS present (the real consume-then-crash
//     case) is tolerated: the first Remove deleted the key, so the second takes the
//     "not found" branch and writes a tombstone.
//   - Replaying the Remove of a key that was NEVER present errors: the first Remove
//     already left a tombstone, and removing an already-removed value is refused.
//
// So "replaying a window is harmless" is false even on the leg that looks forgiving.
// A caller cannot treat the window as a unit, which is the final reason a
// cross-process caller must commit its state first and accept at-most-once.
func TestApplyRemoveReplayDependsOnWhatWasThere(t *testing.T) {
	key := []byte("object-key")
	rm := func(peer ids.ID) map[ids.ID]*Requests {
		return map[ids.ID]*Requests{peer: {RemoveRequests: [][]byte{key}}}
	}

	t.Run("replay after consuming a real object is tolerated", func(t *testing.T) {
		m, cChain, dChain := testMemory(t)
		c := m.NewSharedMemory(cChain)
		d := m.NewSharedMemory(dChain)

		if err := c.Apply(map[ids.ID]*Requests{
			dChain: {PutRequests: []*Element{{Key: key, Value: []byte("v"), Traits: [][]byte{{0x01}}}}},
		}); err != nil {
			t.Fatalf("export failed: %v", err)
		}
		if err := d.Apply(rm(cChain)); err != nil {
			t.Fatalf("first consume failed: %v", err)
		}
		if err := d.Apply(rm(cChain)); err != nil {
			t.Fatalf("replaying the consume of a real object should be tolerated, got: %v", err)
		}
	})

	t.Run("replay of a never-present key errors", func(t *testing.T) {
		m, cChain, dChain := testMemory(t)
		c := m.NewSharedMemory(cChain)

		if err := c.Apply(rm(dChain)); err != nil {
			t.Fatalf("first Remove of an absent key should tombstone, got: %v", err)
		}
		if err := c.Apply(rm(dChain)); err == nil {
			t.Fatal("replaying the Remove of a never-present key returned no error; " +
				"the tombstone should make it a duplicate remove")
		}
	})
}
