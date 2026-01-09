// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package txs

import (
	"context"

	consensusctx "github.com/luxfi/consensus/context"

	"github.com/luxfi/vm/platformvm/fx"
)

var _ UnsignedTx = (*CreateNetworkTx)(nil)

// CreateNetworkTx is an unsigned proposal to create a new chain
type CreateNetworkTx struct {
	// Metadata, inputs and outputs
	BaseTx `serialize:"true"`
	// Who is authorized to manage this chain
	Owner fx.Owner `serialize:"true" json:"owner"`
}

// InitCtx sets the FxID fields in the inputs and outputs of this
// [CreateNetworkTx]. Also sets the [ctx] to the given [vm.ctx] so that
// the addresses can be json marshalled into human readable format
func (tx *CreateNetworkTx) InitCtx(ctx *consensusctx.Context) {
	tx.BaseTx.InitCtx(ctx)
	// Owner doesn't have InitCtx method
}

// SyntacticVerify verifies that this transaction is well-formed
func (tx *CreateNetworkTx) SyntacticVerify(ctx *consensusctx.Context) error {
	switch {
	case tx == nil:
		return ErrNilTx
	case tx.SyntacticallyVerified: // already passed syntactic verification
		return nil
	}

	if err := tx.BaseTx.SyntacticVerify(ctx); err != nil {
		return err
	}
	if err := tx.Owner.Verify(); err != nil {
		return err
	}

	tx.SyntacticallyVerified = true
	return nil
}

func (tx *CreateNetworkTx) Visit(visitor Visitor) error {
	return visitor.CreateNetworkTx(tx)
}

// InitializeWithContext initializes the transaction with consensus context
func (tx *CreateNetworkTx) InitializeWithContext(ctx context.Context) error {
	// Initialize any context-dependent fields here
	return nil
}
