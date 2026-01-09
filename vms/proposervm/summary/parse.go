// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package summary

import (
	"fmt"

	"github.com/luxfi/crypto/hash"
)

func Parse(bytes []byte) (StateSummary, error) {
	summary := stateSummary{
		id:    hash.ComputeHash256Array(bytes),
		bytes: bytes,
	}
	version, err := Codec.Unmarshal(bytes, &summary)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal summary due to: %w", err)
	}
	if version != CodecVersion {
		return nil, errWrongCodecVersion
	}
	return &summary, nil
}
