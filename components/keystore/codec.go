// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keystore

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/ids"
)

// CodecVersion is the wire version of the addresses envelope. On-disk
// schema; bump on any incompatible layout change. Forward-only.
const CodecVersion = uint16(0)

const shortIDLen = 20 // ids.ShortID width

var (
	errShortBuffer    = errors.New("keystore: short buffer")
	errInvalidVersion = errors.New("keystore: invalid version")
)

// marshalAddresses encodes a slice of ShortIDs as:
//
//	u16 version | u32 count | (20B short_id)*
//
// Big-endian. Replaces the prior linearcodec path so the package no
// longer depends on github.com/luxfi/codec. Capacity is bounded by
// maxKeystoreAddresses at the caller (PutKeys).
func marshalAddresses(addresses []ids.ShortID) ([]byte, error) {
	if uint64(len(addresses)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("keystore: too many addresses (%d)", len(addresses))
	}
	out := make([]byte, 2+4+len(addresses)*shortIDLen)
	binary.BigEndian.PutUint16(out[0:2], CodecVersion)
	binary.BigEndian.PutUint32(out[2:6], uint32(len(addresses)))
	off := 6
	for _, addr := range addresses {
		copy(out[off:off+shortIDLen], addr[:])
		off += shortIDLen
	}
	return out, nil
}

func unmarshalAddresses(b []byte) ([]ids.ShortID, error) {
	if len(b) < 2 {
		return nil, errShortBuffer
	}
	ver := binary.BigEndian.Uint16(b[0:2])
	if ver != CodecVersion {
		return nil, fmt.Errorf("%w: got %d want %d", errInvalidVersion, ver, CodecVersion)
	}
	if len(b) < 6 {
		return nil, errShortBuffer
	}
	n := binary.BigEndian.Uint32(b[2:6])
	if uint64(len(b)) < 6+uint64(n)*shortIDLen {
		return nil, errShortBuffer
	}
	addresses := make([]ids.ShortID, n)
	off := uint64(6)
	for i := uint32(0); i < n; i++ {
		copy(addresses[i][:], b[off:off+shortIDLen])
		off += shortIDLen
	}
	return addresses, nil
}
