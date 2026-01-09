// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package nftfx

import (
	"encoding/json"
	"errors"

	"github.com/luxfi/constants"
	"github.com/luxfi/vm/components/verify"
	"github.com/luxfi/vm/secp256k1fx"
	"github.com/luxfi/vm/types"
)

const (
	// MaxPayloadSize is the maximum size that can be placed into a payload
	MaxPayloadSize = constants.KiB
)

var (
	errNilTransferOutput              = errors.New("nil transfer output")
	errPayloadTooLarge                = errors.New("payload too large")
	_                    verify.State = (*TransferOutput)(nil)
)

type TransferOutput struct {
	verify.IsState `serialize:"-" json:"-"`

	GroupID                  uint32              `serialize:"true" json:"groupID"`
	Payload                  types.JSONByteSlice `serialize:"true" json:"payload"`
	secp256k1fx.OutputOwners `serialize:"true"`
}

// MarshalJSON marshals Amt and the embedded OutputOwners struct
// into a JSON readable format
// If OutputOwners cannot be serialized then this will return error
func (out *TransferOutput) MarshalJSON() ([]byte, error) {
	result, err := out.OutputOwners.Fields()
	if err != nil {
		return nil, err
	}

	result["groupID"] = out.GroupID
	result["payload"] = out.Payload
	return json.Marshal(result)
}

func (out *TransferOutput) Verify() error {
	switch {
	case out == nil:
		return errNilTransferOutput
	case len(out.Payload) > MaxPayloadSize:
		return errPayloadTooLarge
	default:
		return out.OutputOwners.Verify()
	}
}
