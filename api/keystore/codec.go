// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keystore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/luxfi/constants"
	"github.com/luxfi/password"
)

// Wire format. The legacy keystore used codec.Manager + linearcodec; this
// package no longer depends on github.com/luxfi/codec. Layout is preserved
// byte-for-byte against linearcodec so existing on-disk user blobs and
// hex-encoded export payloads continue to round-trip.
//
//	passwordHash := u16(version) || [32]byte(Hash.Password) || [16]byte(Hash.Salt)
//	user         := u16(version) || [32]byte(Hash.Password) || [16]byte(Hash.Salt)
//	                                || u32(len(Data))
//	                                || for each kvPair:
//	                                     u32(len(Key))   || Key
//	                                     u32(len(Value)) || Value
//
// All multi-byte integers are big-endian. CodecVersion is 0 — there is no
// "v0 read fallback"; hard cut, one shape. (Wave 2C of codec rip #101.)
const (
	CodecVersion = 0

	// maxPackerSize is the largest blob the keystore will marshal or
	// unmarshal. Bounded at a single GiB to match the pre-rip behaviour.
	maxPackerSize = 1 * constants.GiB
)

var (
	errBlobTooShort   = errors.New("keystore: encoded blob shorter than header")
	errBlobOversized  = errors.New("keystore: encoded blob exceeds maxPackerSize")
	errBlobTrailing   = errors.New("keystore: trailing bytes after decode")
	errUnknownVersion = errors.New("keystore: unknown codec version")
	errKeySliceLen    = errors.New("keystore: kvPair key length exceeds buffer")
	errValSliceLen    = errors.New("keystore: kvPair value length exceeds buffer")
	errDataCountLen   = errors.New("keystore: data count exceeds buffer")
)

// marshalPasswordHash encodes a *password.Hash to its on-disk representation.
func marshalPasswordHash(h *password.Hash) ([]byte, error) {
	if h == nil {
		return nil, errors.New("keystore: cannot marshal nil password hash")
	}
	const size = 2 + len(h.Password) + len(h.Salt) // u16 ver + 32 + 16
	if size > maxPackerSize {
		return nil, errBlobOversized
	}
	out := make([]byte, size)
	binary.BigEndian.PutUint16(out[0:2], CodecVersion)
	copy(out[2:2+len(h.Password)], h.Password[:])
	copy(out[2+len(h.Password):], h.Salt[:])
	return out, nil
}

// unmarshalPasswordHash decodes a *password.Hash from its on-disk
// representation. Returns errUnknownVersion if the leading u16 != CodecVersion.
func unmarshalPasswordHash(b []byte, h *password.Hash) error {
	if h == nil {
		return errors.New("keystore: cannot unmarshal into nil password hash")
	}
	if len(b) > maxPackerSize {
		return errBlobOversized
	}
	const want = 2 + 32 + 16
	if len(b) < want {
		return errBlobTooShort
	}
	if v := binary.BigEndian.Uint16(b[0:2]); v != CodecVersion {
		return fmt.Errorf("%w: %d", errUnknownVersion, v)
	}
	copy(h.Password[:], b[2:2+32])
	copy(h.Salt[:], b[2+32:2+32+16])
	if len(b) != want {
		return errBlobTrailing
	}
	return nil
}

// marshalUser encodes a *user to its on-disk representation.
func marshalUser(u *user) ([]byte, error) {
	if u == nil {
		return nil, errors.New("keystore: cannot marshal nil user")
	}
	// Header: u16 ver + 32 + 16 + u32 count.
	headerLen := 2 + 32 + 16 + 4
	// Bound the body size before allocation to avoid u32 overflow.
	bodyLen := 0
	for _, kv := range u.Data {
		// Defensive: linearcodec used PackBytes which writes a u32 length
		// prefix. A single Key or Value longer than math.MaxUint32 cannot
		// be represented in the wire format.
		if uint64(len(kv.Key)) > math.MaxUint32 {
			return nil, errKeySliceLen
		}
		if uint64(len(kv.Value)) > math.MaxUint32 {
			return nil, errValSliceLen
		}
		bodyLen += 4 + len(kv.Key) + 4 + len(kv.Value)
		if headerLen+bodyLen > maxPackerSize {
			return nil, errBlobOversized
		}
	}
	if uint64(len(u.Data)) > math.MaxUint32 {
		return nil, errDataCountLen
	}
	if headerLen+bodyLen > maxPackerSize {
		return nil, errBlobOversized
	}

	out := make([]byte, headerLen+bodyLen)
	binary.BigEndian.PutUint16(out[0:2], CodecVersion)
	copy(out[2:2+32], u.Hash.Password[:])
	copy(out[2+32:2+32+16], u.Hash.Salt[:])
	binary.BigEndian.PutUint32(out[2+32+16:headerLen], uint32(len(u.Data)))

	off := headerLen
	for _, kv := range u.Data {
		binary.BigEndian.PutUint32(out[off:off+4], uint32(len(kv.Key)))
		off += 4
		copy(out[off:off+len(kv.Key)], kv.Key)
		off += len(kv.Key)
		binary.BigEndian.PutUint32(out[off:off+4], uint32(len(kv.Value)))
		off += 4
		copy(out[off:off+len(kv.Value)], kv.Value)
		off += len(kv.Value)
	}
	return out, nil
}

// unmarshalUser decodes a *user from its on-disk representation.
func unmarshalUser(b []byte, u *user) error {
	if u == nil {
		return errors.New("keystore: cannot unmarshal into nil user")
	}
	if len(b) > maxPackerSize {
		return errBlobOversized
	}
	const headerLen = 2 + 32 + 16 + 4
	if len(b) < headerLen {
		return errBlobTooShort
	}
	if v := binary.BigEndian.Uint16(b[0:2]); v != CodecVersion {
		return fmt.Errorf("%w: %d", errUnknownVersion, v)
	}
	copy(u.Hash.Password[:], b[2:2+32])
	copy(u.Hash.Salt[:], b[2+32:2+32+16])
	count := binary.BigEndian.Uint32(b[2+32+16 : headerLen])

	off := headerLen
	u.Data = make([]kvPair, 0, count)
	for i := uint32(0); i < count; i++ {
		if len(b) < off+4 {
			return errKeySliceLen
		}
		keyLen := binary.BigEndian.Uint32(b[off : off+4])
		off += 4
		if uint64(off)+uint64(keyLen) > uint64(len(b)) {
			return errKeySliceLen
		}
		key := make([]byte, keyLen)
		copy(key, b[off:off+int(keyLen)])
		off += int(keyLen)

		if len(b) < off+4 {
			return errValSliceLen
		}
		valLen := binary.BigEndian.Uint32(b[off : off+4])
		off += 4
		if uint64(off)+uint64(valLen) > uint64(len(b)) {
			return errValSliceLen
		}
		val := make([]byte, valLen)
		copy(val, b[off:off+int(valLen)])
		off += int(valLen)

		u.Data = append(u.Data, kvPair{Key: key, Value: val})
	}
	if off != len(b) {
		return errBlobTrailing
	}
	return nil
}
