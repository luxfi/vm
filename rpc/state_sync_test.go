// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"context"
	"errors"
	"sync"
	"testing"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/vm/chain"
	"github.com/luxfi/vm/chain/blocktest"
)

// syncableVM is a ChainVM that ALSO implements chain.StateSyncableVM, the
// surface the server probes for at construction. baseVM supplies the generic
// contract; the state-sync methods come from the test VM, whose behaviour each
// test sets per call.
type syncableVM struct {
	baseVM
	blocktest.StateSyncableVM
}

var (
	_ chain.ChainVM         = (*syncableVM)(nil)
	_ chain.StateSyncableVM = (*syncableVM)(nil)
)

func newSyncServer(t *testing.T, vm chain.ChainVM) *zapVMServer {
	t.Helper()
	return newZAPVMServer(vm, log.NewTestLogger(log.DebugLevel))
}

func encode(m encoder) []byte {
	buf := zapwire.GetBuffer()
	m.Encode(buf)
	out := append([]byte(nil), buf.Bytes()...)
	zapwire.PutBuffer(buf)
	return out
}

func decodeSummary(t *testing.T, payload []byte) zapwire.SummaryResponse {
	t.Helper()
	resp := zapwire.SummaryResponse{}
	if err := resp.Decode(zapwire.NewReader(payload)); err != nil {
		t.Fatalf("decode summary reply: %v", err)
	}
	return resp
}

func decodeAccept(t *testing.T, payload []byte) zapwire.StateSummaryAcceptResponse {
	t.Helper()
	resp := zapwire.StateSummaryAcceptResponse{}
	if err := resp.Decode(zapwire.NewReader(payload)); err != nil {
		t.Fatalf("decode accept reply: %v", err)
	}
	return resp
}

func decodeEnabled(t *testing.T, payload []byte) zapwire.StateSyncEnabledResponse {
	t.Helper()
	resp := zapwire.StateSyncEnabledResponse{}
	if err := resp.Decode(zapwire.NewReader(payload)); err != nil {
		t.Fatalf("decode state-sync-enabled reply: %v", err)
	}
	return resp
}

// A VM that does not sync state must say so on all six messages. Routed through
// Handle rather than the handlers, so a message left out of the dispatch switch
// fails here: the reply of an unknown message type is empty and decodes into
// nothing.
func TestUnsyncableVMRefusesEveryStateSyncMessage(t *testing.T) {
	s := newSyncServer(t, baseVM{})
	if s.syncVM != nil {
		t.Fatal("a generic VM was probed as state-syncable")
	}
	ctx := context.Background()
	id := ids.GenerateTestID()

	summaryErr := func(t *testing.T, p []byte) zapwire.Error { return decodeSummary(t, p).Err }

	for _, c := range []struct {
		name    string
		op      zapwire.MessageType
		payload []byte
		err     func(*testing.T, []byte) zapwire.Error
	}{
		{"enabled", zapwire.MsgStateSyncEnabled, nil, func(t *testing.T, p []byte) zapwire.Error {
			resp := decodeEnabled(t, p)
			if resp.Enabled {
				t.Fatal("a VM that does not sync state reported sync enabled")
			}
			return resp.Err
		}},
		{"ongoing", zapwire.MsgGetOngoingSyncStateSummary, nil, summaryErr},
		{"last", zapwire.MsgGetLastStateSummary, nil, summaryErr},
		{"parse", zapwire.MsgParseStateSummary, encode(&zapwire.ParseStateSummaryRequest{Bytes: []byte("summary")}), summaryErr},
		{"height", zapwire.MsgGetStateSummary, encode(&zapwire.GetStateSummaryRequest{Height: 7}), summaryErr},
		{"accept", zapwire.MsgStateSummaryAccept, encode(&zapwire.StateSummaryAcceptRequest{ID: id[:]}), func(t *testing.T, p []byte) zapwire.Error {
			return decodeAccept(t, p).Err
		}},
	} {
		_, payload, err := s.Handle(ctx, c.op, c.payload)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := c.err(t, payload); got != zapwire.ErrorStateSyncNotImplemented {
			t.Fatalf("%s: Err = %v, want ErrorStateSyncNotImplemented", c.name, got)
		}
	}
}

// What a caller can read off a summary without holding it: its id, its height,
// its bytes. Each of the four questions that answers with a summary carries all
// three, and carries the argument it was asked with into the VM.
func TestSummaryRoundTrip(t *testing.T) {
	summary := &blocktest.StateSummary{
		IDV:     ids.GenerateTestID(),
		HeightV: 1789,
		BytesV:  []byte("state at 1789"),
	}
	var parsed []byte
	var asked uint64

	vm := &syncableVM{}
	vm.StateSyncEnabledF = func(context.Context) (bool, error) { return true, nil }
	vm.GetOngoingSyncStateSummaryF = func(context.Context) (chain.StateSummary, error) { return summary, nil }
	vm.GetLastStateSummaryF = func(context.Context) (chain.StateSummary, error) { return summary, nil }
	vm.ParseStateSummaryF = func(_ context.Context, b []byte) (chain.StateSummary, error) {
		parsed = b
		return summary, nil
	}
	vm.GetStateSummaryF = func(_ context.Context, h uint64) (chain.StateSummary, error) {
		asked = h
		return summary, nil
	}

	s := newSyncServer(t, vm)
	if s.syncVM == nil {
		t.Fatal("a state-syncable VM was not probed as one")
	}
	ctx := context.Background()

	_, payload, err := s.handleStateSyncEnabled(ctx)
	if err != nil {
		t.Fatalf("enabled: %v", err)
	}
	if resp := decodeEnabled(t, payload); !resp.Enabled || resp.Err != zapwire.ErrorUnspecified {
		t.Fatalf("enabled: %+v", resp)
	}

	for name, payload := range map[string][]byte{
		"ongoing": mustCall(t, func() (zapwire.MessageType, []byte, error) { return s.handleGetOngoingSyncStateSummary(ctx) }),
		"last":    mustCall(t, func() (zapwire.MessageType, []byte, error) { return s.handleGetLastStateSummary(ctx) }),
		"parse": mustCall(t, func() (zapwire.MessageType, []byte, error) {
			return s.handleParseStateSummary(ctx, encode(&zapwire.ParseStateSummaryRequest{Bytes: []byte("peer bytes")}))
		}),
		"height": mustCall(t, func() (zapwire.MessageType, []byte, error) {
			return s.handleGetStateSummary(ctx, encode(&zapwire.GetStateSummaryRequest{Height: 1789}))
		}),
	} {
		resp := decodeSummary(t, payload)
		if resp.Err != zapwire.ErrorUnspecified {
			t.Fatalf("%s: Err = %v", name, resp.Err)
		}
		if id, err := ids.ToID(resp.ID); err != nil || id != summary.IDV {
			t.Fatalf("%s: id = %x (%v), want %s", name, resp.ID, err, summary.IDV)
		}
		if resp.Height != summary.HeightV {
			t.Fatalf("%s: height = %d, want %d", name, resp.Height, summary.HeightV)
		}
		if string(resp.Bytes) != string(summary.BytesV) {
			t.Fatalf("%s: bytes = %q, want %q", name, resp.Bytes, summary.BytesV)
		}
	}

	if string(parsed) != "peer bytes" {
		t.Fatalf("parse reached the VM with %q", parsed)
	}
	if asked != 1789 {
		t.Fatalf("height reached the VM as %d", asked)
	}
}

// A failed question has no answer to carry: Enabled must not come back true off
// a call that did not work.
func TestStateSyncEnabledCarriesNoAnswerWhenItFails(t *testing.T) {
	vm := &syncableVM{}
	vm.StateSyncEnabledF = func(context.Context) (bool, error) {
		return true, errors.New("config unreadable")
	}

	_, payload, err := newSyncServer(t, vm).handleStateSyncEnabled(context.Background())
	if err != nil {
		t.Fatalf("enabled: %v", err)
	}
	resp := decodeEnabled(t, payload)
	if resp.Err != zapwire.ErrorInternal {
		t.Fatalf("Err = %v, want ErrorInternal", resp.Err)
	}
	if resp.Enabled {
		t.Fatal("a failed call reported sync enabled")
	}
}

// Accept names a summary the server handed out; the call reaches that object and
// the mode it decided on comes back.
func TestAcceptReachesTheSummaryTheServerProduced(t *testing.T) {
	accepts := 0
	summary := &blocktest.StateSummary{
		IDV:     ids.GenerateTestID(),
		HeightV: 42,
		BytesV:  []byte("state at 42"),
		AcceptF: func(context.Context) (chain.StateSyncMode, error) {
			accepts++
			return chain.StateSyncDynamic, nil
		},
	}
	vm := &syncableVM{}
	vm.GetLastStateSummaryF = func(context.Context) (chain.StateSummary, error) { return summary, nil }

	s := newSyncServer(t, vm)
	ctx := context.Background()

	if _, _, err := s.handleGetLastStateSummary(ctx); err != nil {
		t.Fatalf("last: %v", err)
	}

	accept := func() zapwire.StateSummaryAcceptResponse {
		t.Helper()
		id := summary.IDV
		_, payload, err := s.handleStateSummaryAccept(ctx, encode(&zapwire.StateSummaryAcceptRequest{ID: id[:]}))
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		return decodeAccept(t, payload)
	}

	resp := accept()
	if resp.Err != zapwire.ErrorUnspecified {
		t.Fatalf("Err = %v, want ErrorUnspecified", resp.Err)
	}
	if resp.Mode != uint8(chain.StateSyncDynamic) {
		t.Fatalf("Mode = %d, want %d", resp.Mode, chain.StateSyncDynamic)
	}
	if accepts != 1 {
		t.Fatalf("the summary was accepted %d times", accepts)
	}

	// The sync now under way supersedes every candidate, so the registry is
	// empty and the same id names nothing a second time.
	if len(s.summaries) != 0 {
		t.Fatalf("registry holds %d summaries after an accept", len(s.summaries))
	}
	if got := accept().Err; got != zapwire.ErrorNotFound {
		t.Fatalf("second accept: Err = %v, want ErrorNotFound", got)
	}
	if accepts != 1 {
		t.Fatalf("the summary was accepted again: %d", accepts)
	}
}

// The security case. The VM holds a perfectly good summary and would hand it
// over if asked; the server was not asked, so the id names nothing here. It is
// refused rather than rebuilt — a summary rebuilt from what a caller sends is
// not the one the network ratified.
func TestAcceptRefusesAnIDTheServerNeverProduced(t *testing.T) {
	accepts, produced := 0, 0
	summary := &blocktest.StateSummary{
		IDV:     ids.GenerateTestID(),
		HeightV: 42,
		BytesV:  []byte("state at 42"),
		AcceptF: func(context.Context) (chain.StateSyncMode, error) {
			accepts++
			return chain.StateSyncStatic, nil
		},
	}
	produce := func() (chain.StateSummary, error) {
		produced++
		return summary, nil
	}

	vm := &syncableVM{}
	vm.GetLastStateSummaryF = func(context.Context) (chain.StateSummary, error) { return produce() }
	vm.GetOngoingSyncStateSummaryF = vm.GetLastStateSummaryF
	vm.ParseStateSummaryF = func(context.Context, []byte) (chain.StateSummary, error) { return produce() }
	vm.GetStateSummaryF = func(context.Context, uint64) (chain.StateSummary, error) { return produce() }

	s := newSyncServer(t, vm)
	id := summary.IDV
	_, payload, err := s.handleStateSummaryAccept(context.Background(), encode(&zapwire.StateSummaryAcceptRequest{ID: id[:]}))
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	if got := decodeAccept(t, payload).Err; got != zapwire.ErrorNotFound {
		t.Fatalf("Err = %v, want ErrorNotFound", got)
	}
	if accepts != 0 {
		t.Fatalf("an id the server never produced was accepted %d times", accepts)
	}
	if produced != 0 {
		t.Fatalf("the server asked the VM for a summary to satisfy an accept (%d times)", produced)
	}
}

// A VM that returns neither a summary nor a reason gets answered for, not
// dereferenced. The handlers are called directly rather than through Handle,
// which recovers: a dereference has to reach the test as a panic.
func TestEmptySummaryAnswerIsRefused(t *testing.T) {
	none := func(context.Context) (chain.StateSummary, error) { return nil, nil }
	vm := &syncableVM{}
	vm.GetLastStateSummaryF = none
	vm.GetOngoingSyncStateSummaryF = none
	vm.ParseStateSummaryF = func(context.Context, []byte) (chain.StateSummary, error) { return nil, nil }
	vm.GetStateSummaryF = func(context.Context, uint64) (chain.StateSummary, error) { return nil, nil }

	s := newSyncServer(t, vm)
	ctx := context.Background()

	for name, payload := range map[string][]byte{
		"ongoing": mustCall(t, func() (zapwire.MessageType, []byte, error) { return s.handleGetOngoingSyncStateSummary(ctx) }),
		"last":    mustCall(t, func() (zapwire.MessageType, []byte, error) { return s.handleGetLastStateSummary(ctx) }),
		"parse": mustCall(t, func() (zapwire.MessageType, []byte, error) {
			return s.handleParseStateSummary(ctx, encode(&zapwire.ParseStateSummaryRequest{Bytes: nil}))
		}),
		"height": mustCall(t, func() (zapwire.MessageType, []byte, error) {
			return s.handleGetStateSummary(ctx, encode(&zapwire.GetStateSummaryRequest{Height: 1}))
		}),
	} {
		if got := decodeSummary(t, payload).Err; got == zapwire.ErrorUnspecified {
			t.Fatalf("%s: an empty answer reported success", name)
		}
	}

	// Nothing was handed out, so nothing can be named later.
	if len(s.summaries) != 0 {
		t.Fatalf("registry holds %d summaries after empty answers", len(s.summaries))
	}
}

// The two failures a syncing caller acts on differently: no summary here, and
// no state sync in this VM at all. Both sentinels for the second name the same
// value, so a VM written against either package is understood.
func TestSummaryFailuresAreNamed(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want zapwire.Error
	}{
		"absent":                 {database.ErrNotFound, zapwire.ErrorNotFound},
		"closed":                 {database.ErrClosed, zapwire.ErrorClosed},
		"declined by the engine": {block.ErrStateSyncableVMNotImplemented, zapwire.ErrorStateSyncNotImplemented},
		"declined by the vm":     {chain.ErrStateSyncableVMNotImplemented, zapwire.ErrorStateSyncNotImplemented},
		"anything else":          {errors.New("disk on fire"), zapwire.ErrorInternal},
	} {
		vm := &syncableVM{}
		vm.GetLastStateSummaryF = func(context.Context) (chain.StateSummary, error) { return nil, c.err }

		_, payload, err := newSyncServer(t, vm).handleGetLastStateSummary(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := decodeSummary(t, payload).Err; got != c.want {
			t.Fatalf("%s: Err = %v, want %v", name, got, c.want)
		}
	}
}

// The registry is what a caller can name later, and a caller decides how much
// of it there is. Past the ceiling the round is forgotten rather than grown.
func TestRegistryIsBounded(t *testing.T) {
	vm := &syncableVM{}
	vm.ParseStateSummaryF = func(_ context.Context, b []byte) (chain.StateSummary, error) {
		return &blocktest.StateSummary{IDV: ids.GenerateTestID(), BytesV: b}, nil
	}

	s := newSyncServer(t, vm)
	ctx := context.Background()
	for i := 0; i < 2*maxSummaries+1; i++ {
		if _, _, err := s.handleParseStateSummary(ctx, encode(&zapwire.ParseStateSummaryRequest{Bytes: []byte{byte(i)}})); err != nil {
			t.Fatalf("parse %d: %v", i, err)
		}
		if len(s.summaries) > maxSummaries {
			t.Fatalf("registry grew to %d after %d parses", len(s.summaries), i+1)
		}
	}
}

// mustCall runs one handler and hands back its reply, so a test reads as the
// sequence of questions it is asking.
func mustCall(t *testing.T, call func() (zapwire.MessageType, []byte, error)) []byte {
	t.Helper()
	_, payload, err := call()
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	return payload
}

// The advertised bit and the servable handlers come from one probe, so a node
// that reads the capability and a node that sends the messages get the same
// answer. Announcing a surface and then refusing it tells a node to stop
// looking elsewhere for something it will not get.
func TestTheAdvertisedBitMatchesWhatIsServed(t *testing.T) {
	logger := log.NewTestLogger(log.DebugLevel)

	syncable := newSyncServer(t, &syncableVM{})
	if syncable.capabilities()&zapwire.CapStateSync == 0 {
		t.Fatal("a state-syncable VM did not advertise CapStateSync")
	}

	plain := newZAPVMServer(baseVM{}, logger)
	if plain.capabilities()&zapwire.CapStateSync != 0 {
		t.Fatal("a VM with no sync surface advertised CapStateSync")
	}
	_, payload, err := plain.handleStateSyncEnabled(context.Background())
	if err != nil {
		t.Fatalf("state sync enabled: %v", err)
	}
	resp := zapwire.StateSyncEnabledResponse{}
	if err := resp.Decode(zapwire.NewReader(payload)); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Err != zapwire.ErrorStateSyncNotImplemented {
		t.Fatalf("Err = %v, want ErrorStateSyncNotImplemented — the bit and the handler disagree", resp.Err)
	}
}

// A summary is accepted once however many callers name it. Accept starts a sync
// that discards the chain below the summary's height; running it twice starts
// that work twice, and the second caller believes it began a sync the VM had
// already begun.
func TestASummaryIsAcceptedOnce(t *testing.T) {
	var mu sync.Mutex
	accepts := 0
	entered, release := make(chan struct{}), make(chan struct{})
	summary := &blocktest.StateSummary{
		IDV: ids.GenerateTestID(), HeightV: 7, BytesV: []byte("state at 7"),
		AcceptF: func(context.Context) (chain.StateSyncMode, error) {
			mu.Lock()
			accepts++
			first := accepts == 1
			mu.Unlock()
			if first {
				// Hold the window open. A second caller now does its lookup while
				// this sync is already running, which is the state a claim that
				// leaves the entry behind cannot distinguish from the first.
				close(entered)
				<-release
			}
			return chain.StateSyncStatic, nil
		},
	}
	vm := &syncableVM{}
	vm.GetLastStateSummaryF = func(context.Context) (chain.StateSummary, error) { return summary, nil }
	s := newSyncServer(t, vm)

	if _, _, err := s.handleGetLastStateSummary(context.Background()); err != nil {
		t.Fatalf("produce: %v", err)
	}
	id := summary.IDV
	req := encode(&zapwire.StateSummaryAcceptRequest{ID: id[:]})

	accept := func() zapwire.Error {
		_, payload, err := s.handleStateSummaryAccept(context.Background(), req)
		if err != nil {
			t.Errorf("accept: %v", err)
			return zapwire.ErrorInternal
		}
		resp := zapwire.StateSummaryAcceptResponse{}
		if err := resp.Decode(zapwire.NewReader(payload)); err != nil {
			t.Errorf("decode: %v", err)
			return zapwire.ErrorInternal
		}
		return resp.Err
	}

	firstErr := make(chan zapwire.Error, 1)
	go func() { firstErr <- accept() }()
	<-entered

	second := accept()
	close(release)

	if got := <-firstErr; got != zapwire.ErrorUnspecified {
		t.Fatalf("the first caller was refused: %v", got)
	}
	if second != zapwire.ErrorNotFound {
		t.Fatalf("a second accept during the first got %v, want ErrorNotFound", second)
	}
	mu.Lock()
	got := accepts
	mu.Unlock()
	if got != 1 {
		t.Fatalf("the VM accepted the same summary %d times", got)
	}
}

// A failed accept reports the reason. Answering ErrorUnspecified would hand the
// caller mode zero — skipped — under the name of a decision the VM never made.
func TestAFailedAcceptIsNotReportedAsSuccess(t *testing.T) {
	boom := errors.New("the trie is unreachable")
	summary := &blocktest.StateSummary{
		IDV: ids.GenerateTestID(), HeightV: 3, BytesV: []byte("state at 3"),
		AcceptF: func(context.Context) (chain.StateSyncMode, error) {
			return chain.StateSyncSkipped, boom
		},
	}
	vm := &syncableVM{}
	vm.GetLastStateSummaryF = func(context.Context) (chain.StateSummary, error) { return summary, nil }
	s := newSyncServer(t, vm)

	if _, _, err := s.handleGetLastStateSummary(context.Background()); err != nil {
		t.Fatalf("produce: %v", err)
	}
	id := summary.IDV
	_, payload, err := s.handleStateSummaryAccept(context.Background(), encode(&zapwire.StateSummaryAcceptRequest{ID: id[:]}))
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	resp := zapwire.StateSummaryAcceptResponse{}
	if err := resp.Decode(zapwire.NewReader(payload)); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Err != zapwire.ErrorInternal {
		t.Fatalf("Err = %v, want ErrorInternal — a failed accept must not carry the success code", resp.Err)
	}
}
