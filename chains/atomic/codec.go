// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package atomic

import (
	"errors"
	"fmt"

	"github.com/luxfi/ids"
	"github.com/luxfi/util/wrappers"
)

// Wire format
//
// All atomic shared-memory wire blobs are length-prefixed-and-versioned:
//
//	[u16 version][... type-specific big-endian fields ...]
//
// Version is currently 0. Only two payload shapes ever reach this codec
// — the cross-chain sharedID seed and the per-key dbElement record. The
// legacy linearcodec wire layout for these shapes is preserved exactly
// so existing on-disk shared-memory state and bootstrapped peers remain
// readable.
//
// Layout per source kind:
//
//   [2]ids.ID  (memory.go::sharedID)
//     [32 id0][32 id1]                                            // raw bytes, no length prefix
//
//   *dbElement (state.go: SetValue/RemoveValue/loadValue)
//     [u8 Present]                                                 // 0/1
//     [u32 nValueBytes][Value bytes]                               // bytes slice
//     [u32 nTraits] ([u32 nTraitBytes][trait bytes])*              // traits slice-of-slice
//
// This is the minimum surface every consumer of vm/chains/atomic
// touches; no other shapes pass through Codec. Adding a new shape is a
// deliberate wire-format extension — register a new case in
// marshalValue/unmarshalValue and bump CodecVersion if the change is
// not backward compatible.

// CodecVersion is the current wire version. Increment on any incompatible
// schema change. There is no "v0 read fallback" — hard cut, one shape.
const CodecVersion = uint16(0)

// Manager is the surface every wire-touching peer of this package needs.
// It is the smallest method set that lets a caller serialize or parse
// an atomic shared-memory record — no reflection registry, no
// codec.Codec sub-interface, no legacy github.com/luxfi/codec import.
//
// The package singleton [Codec] implements [Manager].
type Manager interface {
	Marshal(version uint16, source interface{}) ([]byte, error)
	Unmarshal(bytes []byte, dest interface{}) (uint16, error)
}

// maxAtomicElementSize is the upper bound on a single Marshal/Unmarshal
// blob. The legacy singleton used math.MaxInt; the registered shapes
// (a 64-byte sharedID seed and a dbElement whose Value is bounded by
// the producing chain) never approach the chunk-size limits of any
// real DB backend, but we cap explicitly to refuse pathological inputs
// at unmarshal time instead of letting the underlying packer allocate
// up to memory exhaustion.
const maxAtomicElementSize = 64 * 1024 * 1024 // 64 MiB

// manager is the package-local marshal/unmarshal entry point.
type manager struct {
	maxSize int
}

// Codec is the singleton atomic shared-memory codec. Consumers in this
// package (memory.go, state.go) call Codec.Marshal / Codec.Unmarshal.
var Codec Manager = &manager{maxSize: maxAtomicElementSize}

var (
	ErrUnknownVersion    = errors.New("unknown atomic wire version")
	ErrCantUnpackVersion = errors.New("couldn't unpack atomic version")
	ErrCantPackVersion   = errors.New("couldn't pack atomic version")
	ErrUnsupportedType   = errors.New("unsupported atomic wire type")
	ErrMaxSizeExceeded   = errors.New("max atomic message size exceeded")
	ErrExtraSpace        = errors.New("trailing buffer space in atomic blob")
)

// Marshal serialises a source value with a u16 [version] prefix.
func (m *manager) Marshal(version uint16, source interface{}) ([]byte, error) {
	if version != CodecVersion {
		return nil, ErrCantPackVersion
	}
	p := &wrappers.Packer{MaxSize: m.maxSize}
	p.PackShort(version)
	if p.Errored() {
		return nil, ErrCantPackVersion
	}
	if err := marshalValue(source, p); err != nil {
		return nil, err
	}
	if p.Errored() {
		return nil, p.Err
	}
	return p.Bytes, nil
}

// Unmarshal parses bytes into dest and returns the leading version.
func (m *manager) Unmarshal(bytes []byte, dest interface{}) (uint16, error) {
	if len(bytes) < wrappers.ShortLen {
		return 0, ErrCantUnpackVersion
	}
	if len(bytes) > m.maxSize {
		return 0, ErrMaxSizeExceeded
	}
	p := &wrappers.Packer{Bytes: bytes, MaxSize: m.maxSize}
	version := p.UnpackShort()
	if p.Errored() {
		return 0, ErrCantUnpackVersion
	}
	if version != CodecVersion {
		return version, fmt.Errorf("%w: %d", ErrUnknownVersion, version)
	}
	if err := unmarshalValue(dest, p); err != nil {
		return version, err
	}
	if p.Offset != len(bytes) {
		return version, ErrExtraSpace
	}
	return version, nil
}

// marshalValue dispatches on the concrete shape of [source] and writes
// its body to [p].
//
// The supported shapes mirror the call sites in this package:
//
//   - [2]ids.ID — sharedID seed emitted by memory.go::sharedID
//   - *dbElement — value record stored under each shared-memory key
func marshalValue(source interface{}, p *wrappers.Packer) error {
	switch v := source.(type) {
	case [2]ids.ID:
		marshalIDPair(v, p)
	case *dbElement:
		marshalDBElement(v, p)
	default:
		return fmt.Errorf("%w: %T", ErrUnsupportedType, source)
	}
	if p.Errored() {
		return p.Err
	}
	return nil
}

func unmarshalValue(dest interface{}, p *wrappers.Packer) error {
	switch v := dest.(type) {
	case *dbElement:
		return unmarshalDBElement(v, p)
	case *[2]ids.ID:
		return unmarshalIDPair(v, p)
	default:
		return fmt.Errorf("%w: %T", ErrUnsupportedType, dest)
	}
}

// --- [2]ids.ID --------------------------------------------------------

func marshalIDPair(pair [2]ids.ID, p *wrappers.Packer) {
	p.PackFixedBytes(pair[0][:])
	p.PackFixedBytes(pair[1][:])
}

func unmarshalIDPair(pair *[2]ids.ID, p *wrappers.Packer) error {
	copy(pair[0][:], p.UnpackFixedBytes(ids.IDLen))
	copy(pair[1][:], p.UnpackFixedBytes(ids.IDLen))
	if p.Errored() {
		return p.Err
	}
	return nil
}

// --- *dbElement -------------------------------------------------------

func marshalDBElement(el *dbElement, p *wrappers.Packer) {
	p.PackBool(el.Present)
	p.PackBytes(el.Value)
	p.PackInt(uint32(len(el.Traits)))
	for _, trait := range el.Traits {
		p.PackBytes(trait)
	}
}

func unmarshalDBElement(el *dbElement, p *wrappers.Packer) error {
	el.Present = p.UnpackBool()
	el.Value = p.UnpackBytes()
	nTraits := p.UnpackInt()
	if p.Errored() {
		return p.Err
	}
	el.Traits = make([][]byte, 0, nTraits)
	for i := uint32(0); i < nTraits; i++ {
		el.Traits = append(el.Traits, p.UnpackBytes())
	}
	if p.Errored() {
		return p.Err
	}
	return nil
}
