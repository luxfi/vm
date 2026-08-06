// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package atomiczap carries atomic.SharedMemory across a process boundary over
// ZAP.
//
// WHY IT EXISTS. One atomic.Memory exists per node, and the chain manager carves
// a per-chain SharedMemory handle out of it. A VM linked into the node reads its
// handle straight off runtime.Runtime. A VM hosted as a ZAP plugin — the C-Chain
// EVM and the D-Chain dexvm both are — cannot: the node rebuilds the plugin's
// Runtime from InitializeRequest scalars, and a handle is an interface over a
// live database, not a scalar. So every plugin-hosted VM saw SharedMemory == nil,
// the DEX 0x9999 settlement seam was dark on every chain, and every swap reverted
// "dex: 0x9999 native settle requires the cross-chain atomic capability".
//
// DIRECTION. The node LISTENS and the plugin DIALS. That inversion is what lets
// the existing strictly request/response ZAP transport carry this unchanged — no
// duplex framing, no second demultiplexer, no gRPC. It is the same shape the node
// already uses to hand a plugin its database (DBServerAddr).
//
// WHY BOTH HALVES LIVE HERE. Server and client are one protocol. Splitting them
// across the node and vm repos would make the round trip untestable in either
// (node imports vm, so vm cannot import node) and let the two drift. Keeping them
// in one leaf package beside the interface they carry means the contract is
// pinned by a test that exercises a REAL atomic.Memory through a REAL socket.
package atomiczap

import (
	"context"
	"errors"
	"fmt"
	"net"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/chains/atomic"
)

var (
	// ErrBatchUnsupported: a database.Batch is a live handle on a database the
	// caller's process does not own, so it cannot cross the wire. Refused
	// outright rather than dropped — a silently dropped batch would let a caller
	// believe it had atomicity it does not have. See the Apply doc for why the
	// flush path does not need one.
	ErrBatchUnsupported = errors.New("atomiczap: Apply cannot carry a database batch across a process boundary")

	// ErrGetLengthMismatch guards the invariant every settlement bind rests on:
	// Get returns one value per key, positionally aligned, with an absent object
	// as an EMPTY value. A short or long reply would slide values onto the wrong
	// keys and could bind a credit to the WRONG object, so it is a hard error
	// rather than a best-effort truncation.
	ErrGetLengthMismatch = errors.New("atomiczap: Get returned a value count that does not match the key count")
)

// --- server (node side) ------------------------------------------------------

// Handler answers the atomic messages against one chain's SharedMemory handle.
// One handler per chain, bound to that chain's own handle, so a plugin can only
// ever reach its own partition — the process boundary preserves the chain
// scoping the in-process handle already had.
type Handler struct {
	sm atomic.SharedMemory
}

var _ zapwire.Handler = (*Handler)(nil)

// NewHandler builds the server-side handler for a chain's shared memory.
func NewHandler(sm atomic.SharedMemory) *Handler {
	return &Handler{sm: sm}
}

// Serve binds a loopback listener and serves sm on it until ctx is cancelled,
// returning the bound address and a stop func. Returns ("", noop, nil) when sm
// is nil: the node wired no shared memory for this chain, so the plugin must
// leave its own handle nil and let settlement revert fail-closed. Never
// fabricate a server over a nil handle — that turns a clean "capability absent"
// revert into a nil dereference inside block execution.
func Serve(sm atomic.SharedMemory) (addr string, stop func(), err error) {
	if sm == nil {
		return "", func() {}, nil
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("atomiczap: listen: %w", err)
	}

	srv := zapwire.NewServer(
		zapwire.NewListener(listener, zapwire.DefaultConfig()),
		NewHandler(sm),
	)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = srv.Serve(ctx)
	}()

	return listener.Addr().String(), func() {
		cancel()
		_ = srv.Close()
	}, nil
}

func (h *Handler) Handle(_ context.Context, msgType zapwire.MessageType, payload []byte) (zapwire.MessageType, []byte, error) {
	switch msgType {
	case zapwire.MsgAtomicGet:
		return h.handleGet(payload)
	case zapwire.MsgAtomicIndexed:
		return h.handleIndexed(payload)
	case zapwire.MsgAtomicApply:
		return h.handleApply(payload)
	default:
		// Refuse rather than echo. An unrecognized type here means the peer
		// believes it can do something it cannot, and a silent success would let
		// it proceed as though a cross-chain operation had happened.
		return msgType, nil, fmt.Errorf("atomiczap: unsupported message type %d", msgType)
	}
}

func (h *Handler) handleGet(payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.AtomicGetRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgAtomicGet, nil, fmt.Errorf("atomiczap get: decode: %w", err)
	}
	peerChainID, err := ids.ToID(req.PeerChainID)
	if err != nil {
		return zapwire.MsgAtomicGet, nil, fmt.Errorf("atomiczap get: peerChainID: %w", err)
	}
	values, err := h.sm.Get(peerChainID, req.Keys)
	if err != nil {
		return zapwire.MsgAtomicGet, nil, err
	}
	return encodeResp(zapwire.MsgAtomicGet, (&zapwire.AtomicGetResponse{Values: values}).Encode)
}

func (h *Handler) handleIndexed(payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.AtomicIndexedRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgAtomicIndexed, nil, fmt.Errorf("atomiczap indexed: decode: %w", err)
	}
	peerChainID, err := ids.ToID(req.PeerChainID)
	if err != nil {
		return zapwire.MsgAtomicIndexed, nil, fmt.Errorf("atomiczap indexed: peerChainID: %w", err)
	}
	values, lastTrait, lastKey, err := h.sm.Indexed(
		peerChainID, req.Traits, req.StartTrait, req.StartKey, int(req.Limit),
	)
	if err != nil {
		return zapwire.MsgAtomicIndexed, nil, err
	}
	return encodeResp(zapwire.MsgAtomicIndexed, (&zapwire.AtomicIndexedResponse{
		Values:    values,
		LastTrait: lastTrait,
		LastKey:   lastKey,
	}).Encode)
}

func (h *Handler) handleApply(payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.AtomicApplyRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgAtomicApply, nil, fmt.Errorf("atomiczap apply: decode: %w", err)
	}
	requests := make(map[ids.ID]*atomic.Requests, len(req.Requests))
	for _, wire := range req.Requests {
		peerChainID, err := ids.ToID(wire.PeerChainID)
		if err != nil {
			return zapwire.MsgAtomicApply, nil, fmt.Errorf("atomiczap apply: peerChainID: %w", err)
		}
		ops := &atomic.Requests{
			RemoveRequests: wire.RemoveRequests,
			PutRequests:    make([]*atomic.Element, 0, len(wire.PutRequests)),
		}
		for _, e := range wire.PutRequests {
			ops.PutRequests = append(ops.PutRequests, &atomic.Element{
				Key:    e.Key,
				Value:  e.Value,
				Traits: e.Traits,
			})
		}
		requests[peerChainID] = ops
	}
	if err := h.sm.Apply(requests); err != nil {
		return zapwire.MsgAtomicApply, nil, err
	}
	return zapwire.MsgAtomicApply, nil, nil
}

func encodeResp(msgType zapwire.MessageType, enc func(*zapwire.Buffer)) (zapwire.MessageType, []byte, error) {
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	enc(buf)
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return msgType, out, nil
}

// --- client (plugin side) ----------------------------------------------------

var _ atomic.SharedMemory = (*Client)(nil)

// Client implements atomic.SharedMemory against a remote Handler, so nothing
// above it — not the EVM, not the dexvm, not the DEX precompile — knows the
// memory is out of process.
type Client struct {
	conn *zapwire.Conn
}

// Dial connects to a node-hosted atomic server. A caller holding an empty addr
// must not call this: an absent address means the node wired no shared memory
// for that chain, and the plugin must leave Runtime.SharedMemory nil so
// settlement reverts fail-closed.
func Dial(ctx context.Context, addr string) (*Client, error) {
	cfg := zapwire.DefaultConfig()
	// Get sits on the block-verification path and Apply on the accept path.
	// Neither should inherit a read deadline: a deadline that expires mid-call
	// surfaces as a transport error whose timing differs per node. Every such
	// error is fail-closed at its call site, but not manufacturing them keeps
	// the failure modes honest.
	cfg.ReadTimeout = 0
	conn, err := zapwire.Dial(ctx, addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("atomiczap: dial %q: %w", addr, err)
	}
	return &Client{conn: conn}, nil
}

func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// Get fetches the values a peer chain published for this chain.
//
// ABSENT KEYS ERROR — they do not come back empty. The in-process implementation
// resolves each key through the value database and returns (nil, err) on the
// first miss, so a Get naming ANY absent key fails as a whole. That is faithfully
// reproduced here rather than softened, because softening it would let a caller
// that checks only err conclude an object exists when it does not. On success the
// slice is the same length as keys and positionally aligned, which is the
// invariant every settlement bind rests on and is checked below.
//
// ERROR IDENTITY DOES NOT SURVIVE THE BOUNDARY. The ZAP transport renders a
// remote error as its string, so errors.Is(err, database.ErrNotFound) is false
// here even when the node's handle returned exactly that. No caller depends on
// the distinction today — the DEX settlement path and the D-Chain import path
// both treat any Get error as "no object" — so no presence flag is carried. A
// future caller that needs to tell "absent" from "broken" must add an explicit
// field to AtomicGetResponse; it must not string-match this message.
func (c *Client) Get(peerChainID ids.ID, keys [][]byte) ([][]byte, error) {
	req := &zapwire.AtomicGetRequest{PeerChainID: peerChainID[:], Keys: keys}
	respData, err := c.call(zapwire.MsgAtomicGet, req.Encode)
	if err != nil {
		return nil, fmt.Errorf("atomiczap get: %w", err)
	}
	resp := &zapwire.AtomicGetResponse{}
	if err := resp.Decode(zapwire.NewReader(respData)); err != nil {
		return nil, fmt.Errorf("atomiczap get: decode: %w", err)
	}
	if len(resp.Values) != len(keys) {
		return nil, fmt.Errorf("%w: got %d for %d keys", ErrGetLengthMismatch, len(resp.Values), len(keys))
	}
	return resp.Values, nil
}

// Indexed walks the objects a peer chain published carrying any of the given
// traits, one page at a time.
//
// The D-Chain's autonomous seam drive is what makes this load-bearing rather
// than decorative: inside BuildBlock it enumerates pending C->D intents by a
// fixed discovery trait, recovering each object's key from the LastKey cursor,
// because a shared-memory value does not carry its own key. Without Indexed the
// drive finds nothing and no intent is ever imported.
func (c *Client) Indexed(
	peerChainID ids.ID,
	traits [][]byte,
	startTrait, startKey []byte,
	limit int,
) ([][]byte, []byte, []byte, error) {
	if limit < 0 {
		limit = 0
	}
	req := &zapwire.AtomicIndexedRequest{
		PeerChainID: peerChainID[:],
		Traits:      traits,
		StartTrait:  startTrait,
		StartKey:    startKey,
		Limit:       uint32(limit),
	}
	respData, err := c.call(zapwire.MsgAtomicIndexed, req.Encode)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("atomiczap indexed: %w", err)
	}
	resp := &zapwire.AtomicIndexedResponse{}
	if err := resp.Decode(zapwire.NewReader(respData)); err != nil {
		return nil, nil, nil, fmt.Errorf("atomiczap indexed: decode: %w", err)
	}
	return resp.Values, resp.LastTrait, resp.LastKey, nil
}

// Apply commits a block's cross-chain puts and removes.
//
// EXACTLY-ONCE WITHOUT THE BATCH. In process, Apply takes the caller's database
// batch so the state commit and the shared-memory mutation are one write. That
// batch cannot cross a process boundary, so passing one is refused.
//
// The flush path does not need it. Its request set is derived from a monotone
// seq that is part of consensus state, so a replayed window produces
// byte-identical Puts and Removes, and both are idempotent. At-least-once
// delivery therefore has exactly-once effect — provided the caller advances its
// flushed-seq marker only AFTER this returns. A crash between the Apply and the
// marker advance re-sends the same window, which is a no-op.
func (c *Client) Apply(requests map[ids.ID]*atomic.Requests, batches ...database.Batch) error {
	if len(batches) > 0 {
		return ErrBatchUnsupported
	}
	if len(requests) == 0 {
		return nil
	}
	req := &zapwire.AtomicApplyRequest{Requests: make([]*zapwire.AtomicChainRequests, 0, len(requests))}
	for peerChainID, ops := range requests {
		id := peerChainID
		wire := &zapwire.AtomicChainRequests{
			PeerChainID:    id[:],
			RemoveRequests: ops.RemoveRequests,
			PutRequests:    make([]*zapwire.AtomicElement, 0, len(ops.PutRequests)),
		}
		for _, e := range ops.PutRequests {
			wire.PutRequests = append(wire.PutRequests, &zapwire.AtomicElement{
				Key:    e.Key,
				Value:  e.Value,
				Traits: e.Traits,
			})
		}
		req.Requests = append(req.Requests, wire)
	}
	if _, err := c.call(zapwire.MsgAtomicApply, req.Encode); err != nil {
		return fmt.Errorf("atomiczap apply: %w", err)
	}
	return nil
}

// call encodes a request, sends it, and checks the response type. The type check
// matters: the transport demultiplexes by request id, so a mismatched type means
// the peer answered a different question than the one asked and the payload must
// not be decoded as though it were the expected reply.
func (c *Client) call(msgType zapwire.MessageType, enc func(*zapwire.Buffer)) ([]byte, error) {
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	enc(buf)

	respType, respData, err := c.conn.Call(context.Background(), msgType, buf.Bytes())
	if err != nil {
		return nil, err
	}
	if respType&^(zapwire.MsgResponseFlag|zapwire.MsgErrorFlag) != msgType {
		return nil, fmt.Errorf("unexpected response type %d for request %d", respType, msgType)
	}
	return respData, nil
}
