// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package validatorzap carries validator state across the plugin boundary.
//
// A plugin-hosted VM rebuilds its Runtime from the initialize request, and
// validators.State is an interface over live node-owned state — it cannot be
// copied through a struct literal any more than SharedMemory could. The node
// binds a server over its handle, names the address in the initialize request,
// and the plugin dials it. That is the same shape as chains/atomic/atomiczap,
// deliberately, because it is the same problem.
//
// Until this existed, every plugin VM saw a nil ValidatorState. For most that is
// invisible. For M-Chain it is fatal: its whole job is a threshold ceremony
// among the validator set, so with no way to learn who the validators are it
// answers "no validator committee available" and can never generate a custody
// key, on any network, under any configuration.
package validatorzap

import (
	"context"
	"errors"
	"fmt"
	"net"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/ids"
	"github.com/luxfi/validators"
)

// ErrNoValidatorState is returned by a client whose node wired no handle. It is
// distinct from "the set is empty": an empty validator set is a quorum of
// nobody, and a caller that cannot tell the two apart would form a committee out
// of an absent capability.
var ErrNoValidatorState = errors.New("validatorzap: node wired no validator state for this chain")

// Handler serves one node's validators.State.
type Handler struct {
	vs validators.State
}

var _ zapwire.Handler = (*Handler)(nil)

func NewHandler(vs validators.State) *Handler {
	return &Handler{vs: vs}
}

// Serve binds a listener and serves vs over it, returning the bound address.
//
// A nil handle returns an EMPTY address and no error, exactly as atomiczap does:
// the node genuinely has nothing to serve, and fabricating a server over nil
// would turn a clean "capability absent" into a nil dereference inside whatever
// the plugin does next.
func Serve(vs validators.State) (addr string, stop func(), err error) {
	if vs == nil {
		return "", func() {}, nil
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("validatorzap: listen: %w", err)
	}
	srv := zapwire.NewServer(
		zapwire.NewListener(listener, zapwire.DefaultConfig()),
		NewHandler(vs),
	)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = srv.Serve(ctx)
	}()
	return listener.Addr().String(), func() {
		cancel()
		_ = listener.Close()
	}, nil
}

// method selects which validators.State call a frame carries. It is the first
// payload byte rather than a message type per method, because message types must
// stay below 0x40 (MsgErrorFlag) and no eight-wide run remains there.
type method uint8

const (
	mValidatorSet method = iota
	mCurrentValidators
	mCurrentHeight
	mMinimumHeight
	mChainID
	mNetworkID
	mWarpSet
	mWarpSets
)

func (h *Handler) Handle(ctx context.Context, msgType zapwire.MessageType, payload []byte) (zapwire.MessageType, []byte, error) {
	if msgType != zapwire.MsgValidatorState {
		return 0, nil, fmt.Errorf("validatorzap: unknown message type %d", msgType)
	}
	r := zapwire.NewReader(payload)
	m, err := r.ReadUint8()
	if err != nil {
		return 0, nil, err
	}
	switch method(m) {
	case mValidatorSet:
		return h.handleSet(ctx, r, false)
	case mCurrentValidators:
		return h.handleSet(ctx, r, true)
	case mCurrentHeight:
		return h.handleHeight(ctx, false)
	case mMinimumHeight:
		return h.handleHeight(ctx, true)
	case mChainID:
		return h.handleID(r, false)
	case mNetworkID:
		return h.handleID(r, true)
	case mWarpSet:
		return h.handleWarpSet(ctx, r)
	case mWarpSets:
		return h.handleWarpSets(ctx, r)
	default:
		return 0, nil, fmt.Errorf("validatorzap: unknown method %d", m)
	}
}

// writeValidators encodes a node->validator map. The count is written first so a
// reader allocates exactly once and a truncated frame fails on the next read
// rather than silently yielding a short set — a short validator set is a
// different quorum, not a smaller answer to the same question.
func writeValidators(buf *zapwire.Buffer, set map[ids.NodeID]*validators.GetValidatorOutput) {
	buf.WriteUint32(uint32(len(set)))
	for nodeID, v := range set {
		id := nodeID
		buf.WriteBytes(id[:])
		if v == nil {
			buf.WriteBytes(nil)
			buf.WriteUint64(0)
			continue
		}
		buf.WriteBytes(v.PublicKey)
		buf.WriteUint64(v.Weight)
	}
}

func readValidators(r *zapwire.Reader) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	n, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}
	out := make(map[ids.NodeID]*validators.GetValidatorOutput, n)
	for i := uint32(0); i < n; i++ {
		raw, err := r.ReadBytes()
		if err != nil {
			return nil, err
		}
		nodeID, err := ids.ToNodeID(raw)
		if err != nil {
			return nil, fmt.Errorf("validatorzap: node id: %w", err)
		}
		pub, err := r.ReadBytes()
		if err != nil {
			return nil, err
		}
		weight, err := r.ReadUint64()
		if err != nil {
			return nil, err
		}
		out[nodeID] = &validators.GetValidatorOutput{NodeID: nodeID, PublicKey: pub, Weight: weight}
	}
	return out, nil
}

func (h *Handler) handleSet(ctx context.Context, r *zapwire.Reader, current bool) (zapwire.MessageType, []byte, error) {
	height, err := r.ReadUint64()
	if err != nil {
		return 0, nil, err
	}
	netRaw, err := r.ReadBytes()
	if err != nil {
		return 0, nil, err
	}
	netID, err := ids.ToID(netRaw)
	if err != nil {
		return 0, nil, err
	}

	var set map[ids.NodeID]*validators.GetValidatorOutput
	if current {
		set, err = h.vs.GetCurrentValidators(ctx, height, netID)
	} else {
		set, err = h.vs.GetValidatorSet(ctx, height, netID)
	}
	if err != nil {
		return 0, nil, err
	}
	return encodeResp(zapwire.MsgValidatorState, func(buf *zapwire.Buffer) { writeValidators(buf, set) })
}

func (h *Handler) handleHeight(ctx context.Context, minimum bool) (zapwire.MessageType, []byte, error) {
	var (
		height uint64
		err    error
	)
	if minimum {
		height, err = h.vs.GetMinimumHeight(ctx)
	} else {
		height, err = h.vs.GetCurrentHeight(ctx)
	}
	if err != nil {
		return 0, nil, err
	}
	return encodeResp(zapwire.MsgValidatorState, func(buf *zapwire.Buffer) { buf.WriteUint64(height) })
}

func (h *Handler) handleID(r *zapwire.Reader, network bool) (zapwire.MessageType, []byte, error) {
	raw, err := r.ReadBytes()
	if err != nil {
		return 0, nil, err
	}
	in, err := ids.ToID(raw)
	if err != nil {
		return 0, nil, err
	}
	var out ids.ID
	if network {
		out, err = h.vs.GetNetworkID(in)
	} else {
		out, err = h.vs.GetChainID(in)
	}
	if err != nil {
		return 0, nil, err
	}
	return encodeResp(zapwire.MsgValidatorState, func(buf *zapwire.Buffer) { buf.WriteBytes(out[:]) })
}

func writeWarpSet(buf *zapwire.Buffer, ws *validators.WarpSet) {
	if ws == nil {
		buf.WriteUint64(0)
		buf.WriteUint32(0)
		return
	}
	buf.WriteUint64(ws.Height)
	buf.WriteUint32(uint32(len(ws.Validators)))
	for nodeID, v := range ws.Validators {
		id := nodeID
		buf.WriteBytes(id[:])
		if v == nil {
			buf.WriteBytes(nil)
			buf.WriteBytes(nil)
			buf.WriteUint64(0)
			continue
		}
		buf.WriteBytes(v.PublicKey)
		buf.WriteBytes(v.CoronaPubKey)
		buf.WriteUint64(v.Weight)
	}
}

func readWarpSet(r *zapwire.Reader) (*validators.WarpSet, error) {
	height, err := r.ReadUint64()
	if err != nil {
		return nil, err
	}
	n, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}
	ws := &validators.WarpSet{Height: height, Validators: make(map[ids.NodeID]*validators.WarpValidator, n)}
	for i := uint32(0); i < n; i++ {
		raw, err := r.ReadBytes()
		if err != nil {
			return nil, err
		}
		nodeID, err := ids.ToNodeID(raw)
		if err != nil {
			return nil, err
		}
		pub, err := r.ReadBytes()
		if err != nil {
			return nil, err
		}
		corona, err := r.ReadBytes()
		if err != nil {
			return nil, err
		}
		weight, err := r.ReadUint64()
		if err != nil {
			return nil, err
		}
		ws.Validators[nodeID] = &validators.WarpValidator{
			NodeID: nodeID, PublicKey: pub, CoronaPubKey: corona, Weight: weight,
		}
	}
	return ws, nil
}

func (h *Handler) handleWarpSet(ctx context.Context, r *zapwire.Reader) (zapwire.MessageType, []byte, error) {
	height, err := r.ReadUint64()
	if err != nil {
		return 0, nil, err
	}
	netRaw, err := r.ReadBytes()
	if err != nil {
		return 0, nil, err
	}
	netID, err := ids.ToID(netRaw)
	if err != nil {
		return 0, nil, err
	}
	ws, err := h.vs.GetWarpValidatorSet(ctx, height, netID)
	if err != nil {
		return 0, nil, err
	}
	return encodeResp(zapwire.MsgValidatorState, func(buf *zapwire.Buffer) { writeWarpSet(buf, ws) })
}

func (h *Handler) handleWarpSets(ctx context.Context, r *zapwire.Reader) (zapwire.MessageType, []byte, error) {
	nh, err := r.ReadUint32()
	if err != nil {
		return 0, nil, err
	}
	heights := make([]uint64, 0, nh)
	for i := uint32(0); i < nh; i++ {
		v, err := r.ReadUint64()
		if err != nil {
			return 0, nil, err
		}
		heights = append(heights, v)
	}
	nn, err := r.ReadUint32()
	if err != nil {
		return 0, nil, err
	}
	netIDs := make([]ids.ID, 0, nn)
	for i := uint32(0); i < nn; i++ {
		raw, err := r.ReadBytes()
		if err != nil {
			return 0, nil, err
		}
		id, err := ids.ToID(raw)
		if err != nil {
			return 0, nil, err
		}
		netIDs = append(netIDs, id)
	}

	sets, err := h.vs.GetWarpValidatorSets(ctx, heights, netIDs)
	if err != nil {
		return 0, nil, err
	}
	return encodeResp(zapwire.MsgValidatorState, func(buf *zapwire.Buffer) {
		buf.WriteUint32(uint32(len(sets)))
		for netID, byHeight := range sets {
			id := netID
			buf.WriteBytes(id[:])
			buf.WriteUint32(uint32(len(byHeight)))
			for height, ws := range byHeight {
				buf.WriteUint64(height)
				writeWarpSet(buf, ws)
			}
		}
	})
}

// encodeResp mirrors atomiczap: a pooled buffer, copied out before it is
// returned to the pool. The copy is not optional — the pool reuses the backing
// array, so handing the caller buf.Bytes() would hand it bytes that a later
// response overwrites.
func encodeResp(msgType zapwire.MessageType, enc func(*zapwire.Buffer)) (zapwire.MessageType, []byte, error) {
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	enc(buf)
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return msgType, out, nil
}
