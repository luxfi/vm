// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package validatorzap

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/ids"
	"github.com/luxfi/validators"
)

// fakeState is a node-side validator handle with known contents.
type fakeState struct {
	set      map[ids.NodeID]*validators.GetValidatorOutput
	height   uint64
	chainID  ids.ID
	warpOne  *validators.WarpSet
	warpSets map[ids.ID]map[uint64]*validators.WarpSet
	err      error
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
	if f.warpOne != nil {
		return f.warpOne, f.err
	}
	return &validators.WarpSet{Height: height, Validators: map[ids.NodeID]*validators.WarpValidator{}}, f.err
}
func (f *fakeState) GetWarpValidatorSets(_ context.Context, _ []uint64, _ []ids.ID) (map[ids.ID]map[uint64]*validators.WarpSet, error) {
	if f.warpSets != nil {
		return f.warpSets, f.err
	}
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

// --- the paths a malformed or hostile peer takes -----------------------------

// TestWarpSetsCrossTheBoundary covers the nested map with real content. The
// earlier tests exercised the empty case, which encodes and decodes without ever
// entering the per-validator loops — so the loops were untested while the suite
// looked green.
func TestWarpSetsCrossTheBoundary(t *testing.T) {
	a, b := ids.GenerateTestNodeID(), ids.GenerateTestNodeID()
	netA, netB := ids.GenerateTestID(), ids.GenerateTestID()

	f := &fakeState{
		warpSets: map[ids.ID]map[uint64]*validators.WarpSet{
			netA: {
				10: {Height: 10, Validators: map[ids.NodeID]*validators.WarpValidator{
					a: {NodeID: a, PublicKey: []byte{9, 9}, CoronaPubKey: []byte{7}, Weight: 500},
					b: {NodeID: b, PublicKey: []byte{8}, CoronaPubKey: nil, Weight: 1},
				}},
				11: {Height: 11, Validators: map[ids.NodeID]*validators.WarpValidator{}},
			},
			netB: {20: {Height: 20, Validators: map[ids.NodeID]*validators.WarpValidator{
				a: {NodeID: a, PublicKey: []byte{1}, CoronaPubKey: []byte{2, 3}, Weight: 42},
			}}},
		},
		warpOne: &validators.WarpSet{Height: 5, Validators: map[ids.NodeID]*validators.WarpValidator{
			a: {NodeID: a, PublicKey: []byte{4}, CoronaPubKey: []byte{5}, Weight: 77},
		}},
	}
	c := serveFake(t, f)
	ctx := context.Background()

	got, err := c.GetWarpValidatorSets(ctx, []uint64{10, 11, 20}, []ids.ID{netA, netB})
	if err != nil {
		t.Fatalf("GetWarpValidatorSets: %v", err)
	}
	if len(got) != 2 || len(got[netA]) != 2 || len(got[netB]) != 1 {
		t.Fatalf("shape did not survive: %d nets, netA=%d, netB=%d",
			len(got), len(got[netA]), len(got[netB]))
	}
	if got[netA][10].Validators[a].Weight != 500 || got[netA][10].Validators[b].Weight != 1 {
		t.Fatal("warp weights did not survive the boundary")
	}
	if string(got[netA][10].Validators[a].CoronaPubKey) != string([]byte{7}) {
		t.Fatal("the post-quantum key did not survive the boundary")
	}
	if got[netB][20].Height != 20 {
		t.Fatalf("warp set height = %d, want 20", got[netB][20].Height)
	}

	one, err := c.GetWarpValidatorSet(ctx, 5, netA)
	if err != nil || one == nil {
		t.Fatalf("GetWarpValidatorSet: %+v %v", one, err)
	}
	if one.Validators[a].Weight != 77 || string(one.Validators[a].CoronaPubKey) != string([]byte{5}) {
		t.Fatal("single warp set did not survive")
	}
}

// TestNilValidatorInSetIsCarried: the node's map can hold a nil entry, and the
// encoder writes a zero-weight placeholder for it. Dropping it instead would
// silently shrink the set, and a shorter set is a different quorum.
func TestNilValidatorInSetIsCarried(t *testing.T) {
	a := ids.GenerateTestNodeID()
	c := serveFake(t, &fakeState{
		set:     map[ids.NodeID]*validators.GetValidatorOutput{a: nil},
		warpOne: &validators.WarpSet{Height: 1, Validators: map[ids.NodeID]*validators.WarpValidator{a: nil}},
	})
	got, err := c.GetValidatorSet(context.Background(), 1, ids.Empty)
	if err != nil {
		t.Fatalf("GetValidatorSet: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("a nil entry was DROPPED (%d entries) — that silently shrinks the quorum", len(got))
	}
	if got[a].Weight != 0 {
		t.Fatalf("nil entry decoded with weight %d, want 0", got[a].Weight)
	}
	ws, err := c.GetWarpValidatorSet(context.Background(), 1, ids.Empty)
	if err != nil || len(ws.Validators) != 1 {
		t.Fatalf("nil warp validator was dropped: %+v %v", ws, err)
	}
}

// TestTruncatedFrameLatches walks a valid frame and cuts it at every byte. Every
// prefix must either decode or error — never return a partial set as if it were
// whole, which is the failure the latching scanner exists to make impossible.
func TestTruncatedFrameLatches(t *testing.T) {
	a := ids.GenerateTestNodeID()
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	writeValidatorSet(buf, map[ids.NodeID]*validators.GetValidatorOutput{
		a: {NodeID: a, PublicKey: []byte{1, 2, 3}, Weight: 9},
	})
	full := append([]byte(nil), buf.Bytes()...)

	for cut := 0; cut < len(full); cut++ {
		s := newScan(full[:cut])
		out := s.validatorSet()
		if s.err == nil && len(out) != 1 {
			t.Fatalf("a frame cut at %d/%d decoded %d validators with NO error — "+
				"a partial set must never pass as whole", cut, len(full), len(out))
		}
	}
	// The whole frame still decodes, so the loop above is discriminating.
	s := newScan(full)
	if out := s.validatorSet(); s.err != nil || len(out) != 1 {
		t.Fatalf("the complete frame failed to decode: %v", s.err)
	}
}

// TestTruncatedWarpFramesLatch is the same sweep for the nested encodings, whose
// loops are the deepest and therefore the easiest place for a short read to be
// mistaken for an empty result.
func TestTruncatedWarpFramesLatch(t *testing.T) {
	a := ids.GenerateTestNodeID()
	netA := ids.GenerateTestID()

	for name, write := range map[string]func(*zapwire.Buffer){
		"warpSet": func(b *zapwire.Buffer) {
			writeWarpSet(b, &validators.WarpSet{Height: 3, Validators: map[ids.NodeID]*validators.WarpValidator{
				a: {NodeID: a, PublicKey: []byte{1}, CoronaPubKey: []byte{2}, Weight: 5},
			}})
		},
		"warpSets": func(b *zapwire.Buffer) {
			writeWarpSets(b, map[ids.ID]map[uint64]*validators.WarpSet{
				netA: {3: {Height: 3, Validators: map[ids.NodeID]*validators.WarpValidator{
					a: {NodeID: a, PublicKey: []byte{1}, CoronaPubKey: []byte{2}, Weight: 5},
				}}},
			})
		},
	} {
		buf := zapwire.GetBuffer()
		write(buf)
		full := append([]byte(nil), buf.Bytes()...)
		zapwire.PutBuffer(buf)

		for cut := 0; cut < len(full); cut++ {
			s := newScan(full[:cut])
			if name == "warpSet" {
				ws := s.warpSet()
				if s.err == nil && (ws == nil || len(ws.Validators) != 1) {
					t.Fatalf("%s cut at %d decoded a short set with no error", name, cut)
				}
			} else {
				sets := s.warpSets()
				if s.err == nil && len(sets) != 1 {
					t.Fatalf("%s cut at %d decoded %d nets with no error", name, cut, len(sets))
				}
			}
		}
	}
}

// TestMalformedIDsRejected: an id field is length-prefixed, so a peer can send
// the wrong number of bytes. That must error rather than produce a truncated or
// padded id, because an id that decodes wrong names a different chain.
func TestMalformedIDsRejected(t *testing.T) {
	short := zapwire.GetBuffer()
	defer zapwire.PutBuffer(short)
	short.WriteBytes([]byte{1, 2, 3}) // not 32 bytes

	if s := newScan(append([]byte(nil), short.Bytes()...)); func() bool { s.id(); return s.err == nil }() {
		t.Fatal("a 3-byte id decoded without error")
	}
	if s := newScan(append([]byte(nil), short.Bytes()...)); func() bool { s.nodeID(); return s.err == nil }() {
		t.Fatal("a 3-byte node id decoded without error")
	}
}

// TestUnknownFramesRejected: the handler must refuse a message type it does not
// serve and a method selector it does not know, rather than fall through to a
// default that answers something.
func TestUnknownFramesRejected(t *testing.T) {
	h := NewHandler(&fakeState{})
	if _, _, err := h.Handle(context.Background(), zapwire.MsgAtomicGet, []byte{0}); err == nil {
		t.Fatal("handler answered a message type it does not serve")
	}
	if _, _, err := h.Handle(context.Background(), zapwire.MsgValidatorState, []byte{0xFE}); err == nil {
		t.Fatal("handler answered an unknown method selector")
	}
	if _, _, err := h.Handle(context.Background(), zapwire.MsgValidatorState, nil); err == nil {
		t.Fatal("handler accepted an empty frame")
	}
	// Every method arm must reject a frame that carries no arguments.
	for _, m := range []method{mValidatorSet, mCurrentValidators, mChainID, mNetworkID, mWarpSet, mWarpSets} {
		if _, _, err := h.Handle(context.Background(), zapwire.MsgValidatorState, []byte{byte(m)}); err == nil {
			t.Fatalf("method %d accepted a frame with no arguments", m)
		}
	}
}

// TestEveryMethodSurfacesANodeError: a node-side failure must reach the caller as
// an error on every method. Silently degrading any of them to a zero value is how
// a ceremony would run against the wrong set.
func TestEveryMethodSurfacesANodeError(t *testing.T) {
	c := serveFake(t, &fakeState{err: errors.New("p-chain unavailable")})
	ctx := context.Background()

	if _, err := c.GetCurrentValidators(ctx, 1, ids.Empty); err == nil {
		t.Fatal("GetCurrentValidators swallowed a node error")
	}
	if _, err := c.GetCurrentHeight(ctx); err == nil {
		t.Fatal("GetCurrentHeight swallowed a node error")
	}
	if _, err := c.GetMinimumHeight(ctx); err == nil {
		t.Fatal("GetMinimumHeight swallowed a node error")
	}
	if _, err := c.GetChainID(ids.Empty); err == nil {
		t.Fatal("GetChainID swallowed a node error")
	}
	if _, err := c.GetNetworkID(ids.Empty); err == nil {
		t.Fatal("GetNetworkID swallowed a node error")
	}
	if _, err := c.GetWarpValidatorSet(ctx, 1, ids.Empty); err == nil {
		t.Fatal("GetWarpValidatorSet swallowed a node error")
	}
	if _, err := c.GetWarpValidatorSets(ctx, nil, nil); err == nil {
		t.Fatal("GetWarpValidatorSets swallowed a node error")
	}
}

// TestNilClientRefusesEveryMethod: a client that was never dialed must refuse on
// every method, not just the one the earlier test happened to call.
func TestNilClientRefusesEveryMethod(t *testing.T) {
	var c *Client
	ctx := context.Background()

	if err := c.Close(); err != nil {
		t.Fatalf("Close on a nil client should be a no-op, got %v", err)
	}
	if _, err := c.GetCurrentValidators(ctx, 1, ids.Empty); err == nil {
		t.Fatal("nil client answered GetCurrentValidators")
	}
	if _, err := c.GetCurrentHeight(ctx); err == nil {
		t.Fatal("nil client answered GetCurrentHeight")
	}
	if _, err := c.GetMinimumHeight(ctx); err == nil {
		t.Fatal("nil client answered GetMinimumHeight")
	}
	if _, err := c.GetChainID(ids.Empty); err == nil {
		t.Fatal("nil client answered GetChainID")
	}
	if _, err := c.GetNetworkID(ids.Empty); err == nil {
		t.Fatal("nil client answered GetNetworkID")
	}
	if _, err := c.GetWarpValidatorSet(ctx, 1, ids.Empty); err == nil {
		t.Fatal("nil client answered GetWarpValidatorSet")
	}
	if _, err := c.GetWarpValidatorSets(ctx, nil, nil); err == nil {
		t.Fatal("nil client answered GetWarpValidatorSets")
	}
}

// TestDialRefusesAnUnreachableAddress: a plugin handed a bad address must fail at
// Dial, not later inside a ceremony.
func TestDialRefusesAnUnreachableAddress(t *testing.T) {
	if _, err := Dial(context.Background(), "127.0.0.1:1"); err == nil {
		t.Fatal("dialed an address with nothing behind it")
	}
}

// TestClosedClientIsClosed exercises the live Close path.
func TestClosedClientIsClosed(t *testing.T) {
	c := serveFake(t, &fakeState{set: map[ids.NodeID]*validators.GetValidatorOutput{}})
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// wrongTypeHandler answers with a message type this client did not ask for.
type wrongTypeHandler struct{}

func (wrongTypeHandler) Handle(context.Context, zapwire.MessageType, []byte) (zapwire.MessageType, []byte, error) {
	return zapwire.MsgAtomicGet, []byte{0}, nil
}

// TestWrongResponseTypeRejected: a reply carrying another message type must be
// refused, not decoded. Its bytes would parse as SOMETHING — a count, then
// whatever follows — and the result would be a validator set assembled from an
// unrelated frame, which is a committee assembled from noise.
func TestWrongResponseTypeRejected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := zapwire.NewServer(zapwire.NewListener(ln, zapwire.DefaultConfig()), wrongTypeHandler{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })

	c, err := Dial(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if _, err := c.GetValidatorSet(context.Background(), 1, ids.Empty); err == nil {
		t.Fatal("a reply with the wrong message type was decoded as a validator set")
	}
}

// TestNilWarpSetEncodes: the node may legitimately return a nil WarpSet. The
// encoder must write a well-formed empty set for it rather than panic or emit a
// frame the reader cannot parse.
func TestNilWarpSetEncodes(t *testing.T) {
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	writeWarpSet(buf, nil)

	s := newScan(append([]byte(nil), buf.Bytes()...))
	ws := s.warpSet()
	if s.err != nil {
		t.Fatalf("a nil warp set produced an unreadable frame: %v", s.err)
	}
	if ws == nil || ws.Height != 0 || len(ws.Validators) != 0 {
		t.Fatalf("nil warp set decoded as %+v, want an empty set at height 0", ws)
	}
}

// TestLatchedScanReadsNothingFurther is the scanner's contract, stated directly.
//
// Once a read fails, every later read must return a zero value WITHOUT touching
// the reader. That is what lets the decoders above be straight-line: they read a
// dozen fields and check once at the end, which is only sound if a latched scan
// cannot produce a plausible value from whatever bytes remain.
func TestLatchedScanReadsNothingFurther(t *testing.T) {
	s := newScan(nil)
	if s.u32(); s.err == nil {
		t.Fatal("reading a u32 from an empty frame should latch an error")
	}
	first := s.err

	if v := s.u8(); v != 0 {
		t.Fatalf("a latched scan returned u8 = %d, want 0", v)
	}
	if v := s.u32(); v != 0 {
		t.Fatalf("a latched scan returned u32 = %d, want 0", v)
	}
	if v := s.u64(); v != 0 {
		t.Fatalf("a latched scan returned u64 = %d, want 0", v)
	}
	if v := s.bytes(); v != nil {
		t.Fatalf("a latched scan returned bytes = %x, want nil", v)
	}
	if v := s.id(); v != ids.Empty {
		t.Fatalf("a latched scan returned id = %s, want empty", v)
	}
	if v := s.nodeID(); v != ids.EmptyNodeID {
		t.Fatalf("a latched scan returned nodeID = %s, want empty", v)
	}
	if v := s.validatorSet(); v != nil {
		t.Fatalf("a latched scan returned a validator set of %d, want nil", len(v))
	}
	if v := s.warpSet(); v != nil {
		t.Fatal("a latched scan returned a warp set, want nil")
	}
	if v := s.warpSets(); v != nil {
		t.Fatal("a latched scan returned warp sets, want nil")
	}
	if s.err != first {
		t.Fatal("a later read overwrote the FIRST error — the first failure is the " +
			"one that explains the frame; the rest are its consequences")
	}
}

// TestFrameCannotClaimMoreThanItHolds is a remote denial of service, closed.
//
// Every count on this wire arrives from a peer and sizes an allocation before a
// single entry is read. A four-byte frame claiming four billion validators cost
// EIGHTY-TWO SECONDS and gigabytes of memory — measured, not theorised — because
// make(map, n) honours the claim. The frame is the bound: n entries need at least
// n*minEntry bytes after the count.
//
// It refuses rather than clamps. A clamped count decodes a different set than the
// sender described, and a validator set that quietly loses entries is a different
// quorum.
func TestFrameCannotClaimMoreThanItHolds(t *testing.T) {
	// A count of 4294967295 with no entries behind it.
	huge := []byte{0xFF, 0xFF, 0xFF, 0xFF}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if s := newScan(huge); func() bool { s.validatorSet(); return s.err == nil }() {
			t.Error("a frame claiming 4B validators decoded without error")
		}
		if s := newScan(huge); func() bool { s.warpSets(); return s.err == nil }() {
			t.Error("a frame claiming 4B warp sets decoded without error")
		}
		// warpSet reads a height first, so give it one.
		hugeWarp := append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, huge...)
		if s := newScan(hugeWarp); func() bool { s.warpSet(); return s.err == nil }() {
			t.Error("a warp set claiming 4B validators decoded without error")
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("decoding an oversized claim took over 5s — the allocation is still " +
			"sized from the peer's number, which is a remote denial of service")
	}
}

// TestHonestFramesStillDecode is the other half: the bound must reject only
// impossible claims. A frame that really does carry its entries must pass, or
// the fix would be a denial of service of its own.
func TestHonestFramesStillDecode(t *testing.T) {
	set := map[ids.NodeID]*validators.GetValidatorOutput{}
	for i := 0; i < 64; i++ {
		id := ids.GenerateTestNodeID()
		set[id] = &validators.GetValidatorOutput{NodeID: id, PublicKey: []byte{byte(i)}, Weight: uint64(i + 1)}
	}
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	writeValidatorSet(buf, set)

	s := newScan(append([]byte(nil), buf.Bytes()...))
	got := s.validatorSet()
	if s.err != nil {
		t.Fatalf("an honest 64-validator frame was refused: %v", s.err)
	}
	if len(got) != 64 {
		t.Fatalf("decoded %d of 64 validators", len(got))
	}
}
