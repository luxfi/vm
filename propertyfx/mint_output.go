// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package propertyfx

import (
	consensusctx "github.com/luxfi/consensus/context"

	"github.com/luxfi/vm/components/verify"
	"github.com/luxfi/vm/secp256k1fx"
)

var _ verify.State = (*MintOutput)(nil)

type MintOutput struct {
	verify.IsState `serialize:"-" json:"-"`

	secp256k1fx.OutputOwners `serialize:"true"`
}

func (out *MintOutput) InitCtx(ctx *consensusctx.Context) {
	out.OutputOwners.InitCtx(ctx)
}
