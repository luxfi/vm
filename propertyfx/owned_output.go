// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package propertyfx

import (
	"github.com/luxfi/vm/components/verify"
	"github.com/luxfi/vm/secp256k1fx"
)

var _ verify.State = (*OwnedOutput)(nil)

type OwnedOutput struct {
	verify.IsState `json:"-"`

	secp256k1fx.OutputOwners `serialize:"true"`
}
