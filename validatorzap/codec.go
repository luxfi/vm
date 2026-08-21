// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package validatorzap

import (
	"errors"
	"fmt"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/ids"
	"github.com/luxfi/validators"
)

// ErrMalformedFrame is a frame whose own header contradicts its length.
var ErrMalformedFrame = errors.New("validatorzap: malformed frame")

// scan reads a frame and LATCHES the first error.
//
// Every field on this wire is read as `v, err := r.ReadX(); if err != nil {
// return err }`. Written out, that is two lines of plumbing per field and a
// distinct branch per field, none of which can fail independently: a frame is
// either well-formed or it is not, and one truncated field means the rest is
// garbage. Latching turns a dozen indistinguishable branches into ONE decision at
// the end, so the reads read as the format they describe.
//
// Safety is unchanged because a latched scan returns zero values and callers
// return (nil, err) on the latch — partial data never escapes as if it were
// whole. The alternative is what this replaces: a caller that forgets one of a
// dozen identical checks silently accepts a truncated validator set, which is a
// different quorum.
type scan struct {
	r   *zapwire.Reader
	err error
}

func newScan(payload []byte) *scan { return &scan{r: zapwire.NewReader(payload)} }

func (s *scan) u8() uint8 {
	if s.err != nil {
		return 0
	}
	v, err := s.r.ReadUint8()
	s.err = err
	return v
}

func (s *scan) u32() uint32 {
	if s.err != nil {
		return 0
	}
	v, err := s.r.ReadUint32()
	s.err = err
	return v
}

func (s *scan) u64() uint64 {
	if s.err != nil {
		return 0
	}
	v, err := s.r.ReadUint64()
	s.err = err
	return v
}

func (s *scan) bytes() []byte {
	if s.err != nil {
		return nil
	}
	v, err := s.r.ReadBytes()
	s.err = err
	return v
}

func (s *scan) id() ids.ID {
	raw := s.bytes()
	if s.err != nil {
		return ids.Empty
	}
	v, err := ids.ToID(raw)
	s.err = err
	return v
}

func (s *scan) nodeID() ids.NodeID {
	raw := s.bytes()
	if s.err != nil {
		return ids.EmptyNodeID
	}
	v, err := ids.ToNodeID(raw)
	s.err = err
	return v
}

// count reads a length that will size an allocation, and refuses one the frame
// cannot possibly contain.
//
// The count arrives from a peer and the entries follow it, so a frame can claim
// four billion validators in four bytes. Sizing a map from that claim costs
// eighty seconds and gigabytes before the first entry is read — a remote denial
// of service in a four-byte message. The frame itself is the bound: n entries
// need at least n*minEntry bytes after the count, and anything more is a lie
// about bytes that are not there.
//
// Refuse rather than clamp. A clamped count silently decodes a different set
// than the sender described, and a validator set that quietly loses entries is a
// different quorum.
func (s *scan) count(minEntry int) uint32 {
	n := s.u32()
	if s.err != nil {
		return 0
	}
	if minEntry > 0 && uint64(n)*uint64(minEntry) > uint64(s.r.Remaining()) {
		s.err = fmt.Errorf("%w: frame claims %d entries but holds %d bytes",
			ErrMalformedFrame, n, s.r.Remaining())
		return 0
	}
	return n
}

// validatorSet is the one encoding of a node->validator map, used by both the
// plain and the "current" query. The count leads so a reader allocates once and
// a truncated frame latches on the next read rather than yielding a short set —
// a short validator set is a different quorum, not a smaller answer.
func writeValidatorSet(buf *zapwire.Buffer, set map[ids.NodeID]*validators.GetValidatorOutput) {
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

// minValidatorEntry: a 4-byte length + 20-byte node id, a 4-byte length for the
// key, and an 8-byte weight. The smallest honest entry.
const minValidatorEntry = 4 + 20 + 4 + 8

func (s *scan) validatorSet() map[ids.NodeID]*validators.GetValidatorOutput {
	n := s.count(minValidatorEntry)
	if s.err != nil {
		return nil
	}
	out := make(map[ids.NodeID]*validators.GetValidatorOutput, n)
	for i := uint32(0); i < n; i++ {
		nodeID := s.nodeID()
		pub := s.bytes()
		weight := s.u64()
		if s.err != nil {
			return nil
		}
		out[nodeID] = &validators.GetValidatorOutput{NodeID: nodeID, PublicKey: pub, Weight: weight}
	}
	return out
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

func (s *scan) warpSet() *validators.WarpSet {
	height := s.u64()
	// A warp entry adds a second key length over a validator entry.
	n := s.count(minValidatorEntry + 4)
	if s.err != nil {
		return nil
	}
	ws := &validators.WarpSet{Height: height, Validators: make(map[ids.NodeID]*validators.WarpValidator, n)}
	for i := uint32(0); i < n; i++ {
		nodeID := s.nodeID()
		pub := s.bytes()
		corona := s.bytes()
		weight := s.u64()
		if s.err != nil {
			return nil
		}
		ws.Validators[nodeID] = &validators.WarpValidator{
			NodeID: nodeID, PublicKey: pub, CoronaPubKey: corona, Weight: weight,
		}
	}
	return ws
}

func writeWarpSets(buf *zapwire.Buffer, sets map[ids.ID]map[uint64]*validators.WarpSet) {
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
}

func (s *scan) warpSets() map[ids.ID]map[uint64]*validators.WarpSet {
	// Each net costs a 4-byte length + 32-byte id + a 4-byte inner count.
	n := s.count(4 + 32 + 4)
	if s.err != nil {
		return nil
	}
	out := make(map[ids.ID]map[uint64]*validators.WarpSet, n)
	for i := uint32(0); i < n; i++ {
		netID := s.id()
		// Each height costs 8 bytes plus its warp set's own header.
		m := s.count(8 + 8 + 4)
		if s.err != nil {
			return nil
		}
		byHeight := make(map[uint64]*validators.WarpSet, m)
		for j := uint32(0); j < m; j++ {
			height := s.u64()
			ws := s.warpSet()
			if s.err != nil {
				return nil
			}
			byHeight[height] = ws
		}
		out[netID] = byHeight
	}
	return out
}

// encodeResp mirrors atomiczap: a pooled buffer, copied out before it returns to
// the pool. The copy is not optional — the pool reuses the backing array, so
// handing the caller buf.Bytes() hands it bytes a later response overwrites.
func encodeResp(enc func(*zapwire.Buffer)) (zapwire.MessageType, []byte, error) {
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	enc(buf)
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return zapwire.MsgValidatorState, out, nil
}
