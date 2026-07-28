package chain

import (
	"context"
	"errors"
	"testing"

	"github.com/luxfi/ids"
	"github.com/luxfi/cache/lru"
)

// errInnerAccept is the injected inner-VM failure.
var errInnerAccept = errors.New("inner VM refused to commit")

// failBlock is a Block whose Accept/Reject fail on demand.
type failBlock struct {
	Block
	id         ids.ID
	failAccept bool
	failReject bool
	accepted   bool
	rejected   bool
}

func (b *failBlock) ID() ids.ID    { return b.id }
func (b *failBlock) Bytes() []byte { return b.id[:] } // sized-cache weighs entries via Bytes()
func (b *failBlock) Height() uint64 { return 1 }
func (b *failBlock) Accept(context.Context) error {
	if b.failAccept {
		return errInnerAccept
	}
	b.accepted = true
	return nil
}
func (b *failBlock) Reject(context.Context) error {
	if b.failReject {
		return errInnerAccept
	}
	b.rejected = true
	return nil
}

// TestBlockWrapper_AcceptDoesNotAdvanceStateOnInnerError pins the ordering invariant:
// wrapper caches and lastAcceptedBlock may ONLY move after the inner VM has actually
// accepted. The pre-fix code mutated first and then returned bw.Block.Accept(ctx), so a
// failing inner Accept left lastAcceptedBlock pointing at a block the VM never committed —
// a wrapper-vs-inner split that resurfaces on the next boot as "proposervm finality index
// is BEHIND the inner VM tip" and refuses to initialize the chain.
func TestBlockWrapper_AcceptDoesNotAdvanceStateOnInnerError(t *testing.T) {
	prevID, blkID := ids.GenerateTestID(), ids.GenerateTestID()
	prev := &BlockWrapper{Block: &failBlock{id: prevID}}

	st := &State{
		verifiedBlocks:    map[ids.ID]*BlockWrapper{},
		lastAcceptedBlock: prev,
	}
	st.decidedBlocks = lru.NewSizedCache[ids.ID, *BlockWrapper](1<<20, cachedBlockSize)

	inner := &failBlock{id: blkID, failAccept: true}
	bw := &BlockWrapper{Block: inner, state: st}
	st.verifiedBlocks[blkID] = bw

	if err := bw.Accept(context.Background()); !errors.Is(err, errInnerAccept) {
		t.Fatalf("expected the inner error to propagate, got %v", err)
	}
	if st.lastAcceptedBlock != prev {
		t.Fatal("lastAcceptedBlock MOVED despite the inner VM refusing to accept")
	}
	if _, ok := st.verifiedBlocks[blkID]; !ok {
		t.Fatal("block was dropped from verifiedBlocks despite a failed Accept")
	}
	if _, ok := st.decidedBlocks.Get(blkID); ok {
		t.Fatal("block was cached as DECIDED despite a failed Accept")
	}

	// Positive control: a succeeding Accept must advance everything.
	inner.failAccept = false
	if err := bw.Accept(context.Background()); err != nil {
		t.Fatalf("clean Accept failed: %v", err)
	}
	if st.lastAcceptedBlock != bw {
		t.Fatal("lastAcceptedBlock did NOT advance on a successful Accept")
	}
	if _, ok := st.verifiedBlocks[blkID]; ok {
		t.Fatal("accepted block still in verifiedBlocks")
	}
	if _, ok := st.decidedBlocks.Get(blkID); !ok {
		t.Fatal("accepted block not cached as decided")
	}
}

// TestBlockWrapper_RejectDoesNotCacheOnInnerError is the Reject-side mirror.
func TestBlockWrapper_RejectDoesNotCacheOnInnerError(t *testing.T) {
	blkID := ids.GenerateTestID()
	st := &State{verifiedBlocks: map[ids.ID]*BlockWrapper{}}
	st.decidedBlocks = lru.NewSizedCache[ids.ID, *BlockWrapper](1<<20, cachedBlockSize)

	inner := &failBlock{id: blkID, failReject: true}
	bw := &BlockWrapper{Block: inner, state: st}
	st.verifiedBlocks[blkID] = bw

	if err := bw.Reject(context.Background()); !errors.Is(err, errInnerAccept) {
		t.Fatalf("expected the inner error to propagate, got %v", err)
	}
	if _, ok := st.verifiedBlocks[blkID]; !ok {
		t.Fatal("block dropped from verifiedBlocks despite a failed Reject")
	}
	if _, ok := st.decidedBlocks.Get(blkID); ok {
		t.Fatal("block cached as DECIDED despite a failed Reject")
	}
}
