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
	ids2 "github.com/luxfi/ids"
	"github.com/luxfi/validators"
)

// ErrNoValidatorState is returned by a client whose node wired no handle.
//
// It is distinct from "the set is empty", and the distinction is the point: they
// are the same bytes and opposite facts. An empty validator set is a quorum of
// nobody, so a caller that could not tell them apart would form a committee out
// of an absent capability.
var ErrNoValidatorState = errors.New("validatorzap: node wired no validator state for this chain")

// method selects which validators.State call a frame carries. It is the first
// payload byte rather than a message type per method, because message types must
// stay below 0x40 — MsgErrorFlag IS 0x40, so a type with bit 6 set arrives
// indistinguishable from an error — and no eight-wide run remains there.
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

// Handler serves one node's validators.State.
type Handler struct {
	vs validators.State
}

var _ zapwire.Handler = (*Handler)(nil)

func NewHandler(vs validators.State) *Handler { return &Handler{vs: vs} }

// Serve binds a listener and serves vs over it, returning the bound address.
//
// A nil handle returns an EMPTY address and no error, exactly as atomiczap does:
// the node genuinely has nothing to serve, and a server over nil would turn a
// clean "capability absent" into a nil dereference inside whatever the plugin
// does next.
func Serve(vs validators.State) (addr string, stop func(), err error) {
	if vs == nil {
		return "", func() {}, nil
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("validatorzap: listen: %w", err)
	}
	srv := zapwire.NewServer(zapwire.NewListener(listener, zapwire.DefaultConfig()), NewHandler(vs))
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()
	return listener.Addr().String(), func() {
		cancel()
		_ = listener.Close()
	}, nil
}

// Handle answers one query. Each arm reads its arguments, calls the node, and
// encodes the reply; the scan latches any malformed frame so the arms describe
// the format rather than re-checking it field by field.
func (h *Handler) Handle(ctx context.Context, msgType zapwire.MessageType, payload []byte) (zapwire.MessageType, []byte, error) {
	if msgType != zapwire.MsgValidatorState {
		return 0, nil, fmt.Errorf("validatorzap: unknown message type %d", msgType)
	}
	s := newScan(payload)
	m := method(s.u8())
	if s.err != nil {
		return 0, nil, s.err
	}

	switch m {
	case mValidatorSet, mCurrentValidators:
		height, netID := s.u64(), s.id()
		if s.err != nil {
			return 0, nil, s.err
		}
		get := h.vs.GetValidatorSet
		if m == mCurrentValidators {
			get = h.vs.GetCurrentValidators
		}
		set, err := get(ctx, height, netID)
		if err != nil {
			return 0, nil, err
		}
		return encodeResp(func(buf *zapwire.Buffer) { writeValidatorSet(buf, set) })

	case mCurrentHeight, mMinimumHeight:
		get := h.vs.GetCurrentHeight
		if m == mMinimumHeight {
			get = h.vs.GetMinimumHeight
		}
		height, err := get(ctx)
		if err != nil {
			return 0, nil, err
		}
		return encodeResp(func(buf *zapwire.Buffer) { buf.WriteUint64(height) })

	case mChainID, mNetworkID:
		in := s.id()
		if s.err != nil {
			return 0, nil, s.err
		}
		get := h.vs.GetChainID
		if m == mNetworkID {
			get = h.vs.GetNetworkID
		}
		out, err := get(in)
		if err != nil {
			return 0, nil, err
		}
		return encodeResp(func(buf *zapwire.Buffer) { buf.WriteBytes(out[:]) })

	case mWarpSet:
		height, netID := s.u64(), s.id()
		if s.err != nil {
			return 0, nil, s.err
		}
		ws, err := h.vs.GetWarpValidatorSet(ctx, height, netID)
		if err != nil {
			return 0, nil, err
		}
		return encodeResp(func(buf *zapwire.Buffer) { writeWarpSet(buf, ws) })

	case mWarpSets:
		nh := s.u32()
		heights := make([]uint64, 0, nh)
		for i := uint32(0); i < nh; i++ {
			heights = append(heights, s.u64())
		}
		nn := s.u32()
		netIDs := make([]ids2.ID, 0, nn)
		for i := uint32(0); i < nn; i++ {
			netIDs = append(netIDs, s.id())
		}
		if s.err != nil {
			return 0, nil, s.err
		}
		sets, err := h.vs.GetWarpValidatorSets(ctx, heights, netIDs)
		if err != nil {
			return 0, nil, err
		}
		return encodeResp(func(buf *zapwire.Buffer) { writeWarpSets(buf, sets) })

	default:
		return 0, nil, fmt.Errorf("validatorzap: unknown method %d", m)
	}
}
