// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package message

import (
	"github.com/luxfi/codec"
	"github.com/luxfi/codec/linearcodec"
	"github.com/luxfi/constants"
)

const (
	codecVersion   = 0
	maxMessageSize = 512 * constants.KiB
	maxSliceLen    = maxMessageSize
)

// Codec does serialization and deserialization
var c codec.Manager

func init() {
	c = codec.NewManager(maxMessageSize)
	lc := linearcodec.NewDefault()

	if err := lc.RegisterType(&Tx{}); err != nil {
		panic(err)
	}
	if err := c.RegisterCodec(codecVersion, lc); err != nil {
		panic(err)
	}
}
