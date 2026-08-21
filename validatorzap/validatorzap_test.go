// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package validatorzap

import (
	"context"
	"errors"
	"testing"

	"github.com/luxfi/ids"
	"github.com/luxfi/validators"
)

// fakeState is a node-side validator handle with known contents.
type fakeState struct {
	set     map[ids.NodeID]*validators.GetValidatorOutput
	height  uint64
	chainID ids.ID
	err     error
}

func (f *fakeState) GetValidatorSet(_ context.Context, _ uint64, _ ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	return f.set, f.err
}
func (f *fakeState) GetCurrentValidators(_ context.Context, _ uint64, _ ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	return f.set, f.err
}
func (f *fakeState) GetCurrentHeight(context.Context) (uint64, error) { return f.height, f.err }
func (f *fakeState) GetMinimumHeight(context.Context) (uint64, error) { return f.height / 2, f.err }
func (f *fakeState) GetChainID(ids.ID) (ids.ID, error)               { return f.chainID, f.err }
func (f *fakeState) GetNetworkID(ids.ID) (ids.ID, error)             { return f.chainID, f.err }
func (f *fakeState) GetWarpValidatorSet(_ context.Context, height uint64, _ ids.ID) (*validators.WarpSet, error) {
	return &validators.WarpSet{Height: height, Validators: map[ids.NodeID]*validators.WarpValidator{}}, f.err
}
func (f *fakeState) GetWarpValidatorSets(_ context.Context, _ []uint64, _ []ids.ID) (map[ids.ID]map[uint64]*validators.WarpSet, error) {
	return map[ids.ID]map[uint64]*validators.WarpSet{}, f.err
}

func serveFake(t *testing.T, f *fakeState) *Client {
	t.Helper()
	addr, stop, err := Serve(f)
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	t.Cleanup(stop)
	c, err := Dial(context.Background(), addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestValidatorSetCrossesTheBoundary is the property M-Chain could not form a
// committee without: the set the node holds must arrive at the plugin intact —
// every node id, every weight. A weight that does not survive is a different
// quorum, and custody seats are allocated by weight.
func TestValidatorSetCrossesTheBoundary(t *testing.T) {
	a, b := ids.GenerateTestNodeID(), ids.GenerateTestNodeID()
	f := &fakeState{
		set: map[ids.NodeID]*validators.GetValidatorOutput{
			a: {NodeID: a, PublicKey: []byte{1, 2, 3}, Weight: 1_000_000},
			b: {NodeID: b, PublicKey: []byte{4, 5}, Weight: 7},
		},
		height:  42,
		chainID: ids.GenerateTestID(),
	}
	c := serveFake(t, f)

	got, err := c.GetValidatorSet(context.Background(), 1, ids.Empty)
	if err != nil {
		t.Fatalf("GetValidatorSet: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d validators, want 2 — a short set is a different quorum", len(got))
	}
	if got[a].Weight != 1_000_000 || got[b].Weight != 7 {
		t.Fatalf("weights did not survive: %d, %d — custody seats are allocated by weight",
			got[a].Weight, got[b].Weight)
	}
	if string(got[a].PublicKey) != string([]byte{1, 2, 3}) {
		t.Fatalf("public key did not survive: %x", got[a].PublicKey)
	}
	if got[a].NodeID != a || got[b].NodeID != b {
		t.Fatal("node ids did not survive the boundary")
	}
}

// TestEveryMethodAnswers: the client implements the FULL validators.State, not
// just the one method M-Chain calls today. A method that silently returned zero
// would hand a caller a plausible wrong answer.
func TestEveryMethodAnswers(t *testing.T) {
	f := &fakeState{
		set:     map[ids.NodeID]*validators.GetValidatorOutput{},
		height:  100,
		chainID: ids.GenerateTestID(),
	}
	c := serveFake(t, f)
	ctx := context.Background()

	if h, err := c.GetCurrentHeight(ctx); err != nil || h != 100 {
		t.Fatalf("GetCurrentHeight = %d, %v; want 100", h, err)
	}
	if h, err := c.GetMinimumHeight(ctx); err != nil || h != 50 {
		t.Fatalf("GetMinimumHeight = %d, %v; want 50", h, err)
	}
	if id, err := c.GetChainID(ids.Empty); err != nil || id != f.chainID {
		t.Fatalf("GetChainID = %s, %v", id, err)
	}
	if id, err := c.GetNetworkID(ids.Empty); err != nil || id != f.chainID {
		t.Fatalf("GetNetworkID = %s, %v", id, err)
	}
	if ws, err := c.GetWarpValidatorSet(ctx, 7, ids.Empty); err != nil || ws == nil || ws.Height != 7 {
		t.Fatalf("GetWarpValidatorSet = %+v, %v", ws, err)
	}
	if _, err := c.GetWarpValidatorSets(ctx, []uint64{1, 2}, []ids.ID{ids.Empty}); err != nil {
		t.Fatalf("GetWarpValidatorSets: %v", err)
	}
	if _, err := c.GetCurrentValidators(ctx, 1, ids.Empty); err != nil {
		t.Fatalf("GetCurrentValidators: %v", err)
	}
}

// TestAbsentCapabilityIsNotAnEmptySet is the distinction the whole design turns
// on. A node that wired no validator state must produce a REFUSAL, never an
// empty set: an empty validator set is a quorum of nobody, and a caller that
// cannot tell the two apart would form a committee out of an absent capability.
func TestAbsentCapabilityIsNotAnEmptySet(t *testing.T) {
	addr, stop, err := Serve(nil)
	if err != nil {
		t.Fatalf("Serve(nil) must not error: %v", err)
	}
	t.Cleanup(stop)
	if addr != "" {
		t.Fatal("Serve(nil) returned an address — a server over a nil handle is a lie")
	}

	if _, err := Dial(context.Background(), ""); !errors.Is(err, ErrNoValidatorState) {
		t.Fatalf("Dial(\"\") = %v, want ErrNoValidatorState", err)
	}

	var nilClient *Client
	if _, err := nilClient.GetValidatorSet(context.Background(), 1, ids.Empty); err == nil {
		t.Fatal("a nil client returned a validator set instead of refusing — " +
			"that set would be empty, and an empty set is a quorum of nobody")
	}
}

// TestServerErrorReachesTheCaller: a node-side failure must surface as an error,
// not as an empty set. Committee formation reads this; silently degrading a
// failed read to "no validators" is how a ceremony would run with the wrong set.
func TestServerErrorReachesTheCaller(t *testing.T) {
	c := serveFake(t, &fakeState{err: errors.New("p-chain unavailable")})
	if _, err := c.GetValidatorSet(context.Background(), 1, ids.Empty); err == nil {
		t.Fatal("a failing node handle produced no error at the plugin")
	}
}
