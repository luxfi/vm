// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package atomic

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

// TestCodec_IDPair_WireFormat verifies the byte layout of a [2]ids.ID
// Marshal call. This is the seed value that memory.go::sharedID hashes
// to produce a deterministic cross-chain prefix. Any wire-format change
// here invalidates every existing shared-memory record on every node.
//
// Layout: [u16 version=0][32 id0][32 id1]  -> 66 bytes total.
func TestCodec_IDPair_WireFormat(t *testing.T) {
	require := require.New(t)

	var id0 ids.ID
	for i := range id0 {
		id0[i] = byte(i + 1)
	}
	var id1 ids.ID
	for i := range id1 {
		id1[i] = byte(0xff - i)
	}

	got, err := Codec.Marshal(CodecVersion, [2]ids.ID{id0, id1})
	require.NoError(err)
	require.Len(got, 2+32+32)

	// Version prefix.
	require.Equal(byte(0x00), got[0])
	require.Equal(byte(0x00), got[1])
	// id0 raw.
	require.True(bytes.Equal(got[2:34], id0[:]))
	// id1 raw.
	require.True(bytes.Equal(got[34:66], id1[:]))
}

// TestCodec_DBElement_WireFormat pins the byte layout of a dbElement
// blob. dbElement is the value stored under each shared-memory key by
// state.go::SetValue/RemoveValue and read back by loadValue. Bit-shape
// must match the pre-rip linearcodec layout so any on-disk record from
// the legacy build still parses.
//
// Body layout:
//   [u8  Present]
//   [u32 nValueBytes][Value bytes]
//   [u32 nTraits] ([u32 nTraitBytes][trait bytes])*
//
// With Present=true, Value=[0xab,0xcd,0xef], Traits=[[0x01],[0x02,0x03]]
// the wire body is:
//   01 00000003 abcdef 00000002 00000001 01 00000002 0203
// prefixed by the codec version 0000.
func TestCodec_DBElement_WireFormat(t *testing.T) {
	require := require.New(t)

	in := &dbElement{
		Present: true,
		Value:   []byte{0xab, 0xcd, 0xef},
		Traits:  [][]byte{{0x01}, {0x02, 0x03}},
	}
	want := []byte{
		0x00, 0x00, // version
		0x01,                   // Present
		0x00, 0x00, 0x00, 0x03, // len(Value)
		0xab, 0xcd, 0xef, // Value
		0x00, 0x00, 0x00, 0x02, // len(Traits)
		0x00, 0x00, 0x00, 0x01, // len(Traits[0])
		0x01,                   // Traits[0]
		0x00, 0x00, 0x00, 0x02, // len(Traits[1])
		0x02, 0x03, // Traits[1]
	}

	got, err := Codec.Marshal(CodecVersion, in)
	require.NoError(err)
	require.Equal(want, got)

	roundtrip := &dbElement{}
	v, err := Codec.Unmarshal(got, roundtrip)
	require.NoError(err)
	require.Equal(CodecVersion, v)
	require.Equal(in.Present, roundtrip.Present)
	require.Equal(in.Value, roundtrip.Value)
	require.Equal(in.Traits, roundtrip.Traits)
}

// TestCodec_DBElement_Tombstone covers the Present=false tombstone case
// emitted by RemoveValue when a key is being optimistically deleted
// before it has ever been put. The tombstone has empty Value and Traits.
func TestCodec_DBElement_Tombstone(t *testing.T) {
	require := require.New(t)

	in := &dbElement{Present: false}
	want := []byte{
		0x00, 0x00, // version
		0x00,                   // Present
		0x00, 0x00, 0x00, 0x00, // len(Value)
		0x00, 0x00, 0x00, 0x00, // len(Traits)
	}

	got, err := Codec.Marshal(CodecVersion, in)
	require.NoError(err)
	require.Equal(want, got)

	roundtrip := &dbElement{}
	_, err = Codec.Unmarshal(got, roundtrip)
	require.NoError(err)
	require.False(roundtrip.Present)
	require.Empty(roundtrip.Value)
	require.Empty(roundtrip.Traits)
}

// TestCodec_UnsupportedType_Rejected verifies that any source type
// outside the registered set is rejected at Marshal time. The codec is
// closed by design — adding a shape is a deliberate change.
func TestCodec_UnsupportedType_Rejected(t *testing.T) {
	require := require.New(t)

	_, err := Codec.Marshal(CodecVersion, &struct{ X int }{X: 1})
	require.ErrorIs(err, ErrUnsupportedType)

	_, err = Codec.Marshal(CodecVersion, "hello")
	require.ErrorIs(err, ErrUnsupportedType)

	_, err = Codec.Marshal(CodecVersion, 42)
	require.ErrorIs(err, ErrUnsupportedType)
}

// TestCodec_UnknownVersion verifies that an Unmarshal call with a
// version other than CodecVersion is rejected. There is no read
// fallback for older versions; bumping CodecVersion is a hard cut.
func TestCodec_UnknownVersion(t *testing.T) {
	require := require.New(t)

	bad := []byte{0x00, 0x01, 0x00} // version=1 + bool
	dst := &dbElement{}
	_, err := Codec.Unmarshal(bad, dst)
	require.ErrorIs(err, ErrUnknownVersion)
}

// TestCodec_VersionTooShort verifies that a blob smaller than the
// version prefix is rejected cleanly instead of panicking.
func TestCodec_VersionTooShort(t *testing.T) {
	require := require.New(t)

	_, err := Codec.Unmarshal([]byte{0x00}, &dbElement{})
	require.ErrorIs(err, ErrCantUnpackVersion)

	_, err = Codec.Unmarshal(nil, &dbElement{})
	require.ErrorIs(err, ErrCantUnpackVersion)
}

// TestCodec_TrailingBytes verifies the codec refuses blobs that decode
// the requested type but leave trailing buffer space — this would
// otherwise let a peer smuggle bytes past a strict reader.
func TestCodec_TrailingBytes(t *testing.T) {
	require := require.New(t)

	good, err := Codec.Marshal(CodecVersion, &dbElement{
		Present: false,
	})
	require.NoError(err)
	tampered := append(good, 0xaa)

	_, err = Codec.Unmarshal(tampered, &dbElement{})
	require.ErrorIs(err, ErrExtraSpace)
}

// TestCodec_PackVersion_Mismatch verifies Marshal refuses to emit a
// blob under a version this codec doesn't support. The behaviour
// mirrors the legacy codec.Manager.Marshal(version=non-zero) path.
func TestCodec_PackVersion_Mismatch(t *testing.T) {
	require := require.New(t)

	_, err := Codec.Marshal(CodecVersion+1, [2]ids.ID{})
	require.True(errors.Is(err, ErrCantPackVersion))
}
