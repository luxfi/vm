// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package executor

import (
	"errors"
	"fmt"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/components/verify"
	"github.com/luxfi/vm/platformvm/fx"
	"github.com/luxfi/vm/vms/platformvm/state"
	"github.com/luxfi/vm/vms/platformvm/txs"
)

var (
	errWrongNumberOfCredentials = errors.New("should have the same number of credentials as inputs")
	errIsImmutable              = errors.New("is immutable")
	errUnauthorizedModification = errors.New("unauthorized modification")
)

// verifyPoAChainAuthorization carries out the validation for modifying a PoA
// chain. This is an extension of [verifyChainAuthorization] that additionally
// verifies that the chain being modified is currently a PoA chain.
func verifyPoAChainAuthorization(
	fx fx.Fx,
	chainState state.Chain,
	sTx *txs.Tx,
	chainID ids.ID,
	chainAuth verify.Verifiable,
) ([]verify.Verifiable, error) {
	creds, err := verifyChainAuthorization(fx, chainState, sTx, chainID, chainAuth)
	if err != nil {
		return nil, err
	}

	_, err = chainState.GetNetTransformation(chainID)
	if err == nil {
		return nil, fmt.Errorf("%q %w", chainID, errIsImmutable)
	}
	if err != database.ErrNotFound {
		return nil, err
	}

	_, err = chainState.GetNetToL1Conversion(chainID)
	if err == nil {
		return nil, fmt.Errorf("%q %w", chainID, errIsImmutable)
	}
	if err != database.ErrNotFound {
		return nil, err
	}

	return creds, nil
}

// verifyChainAuthorization carries out the validation for modifying a chain.
// The last credential in [tx.Creds] is used as the chain authorization.
// Returns the remaining tx credentials that should be used to authorize the
// other operations in the tx.
func verifyChainAuthorization(
	fx fx.Fx,
	chainState state.Chain,
	tx *txs.Tx,
	chainID ids.ID,
	chainAuth verify.Verifiable,
) ([]verify.Verifiable, error) {
	chainOwner, err := chainState.GetNetOwner(chainID)
	if err != nil {
		return nil, err
	}

	return verifyAuthorization(fx, tx, chainOwner, chainAuth)
}

// verifyAuthorization carries out the validation of an auth. The last
// credential in [tx.Creds] is used as the authorization.
// Returns the remaining tx credentials that should be used to authorize the
// other operations in the tx.
func verifyAuthorization(
	fx fx.Fx,
	tx *txs.Tx,
	owner fx.Owner,
	auth verify.Verifiable,
) ([]verify.Verifiable, error) {
	if len(tx.Creds) == 0 {
		// Ensure there is at least one credential for the chain authorization
		return nil, errWrongNumberOfCredentials
	}

	baseTxCredsLen := len(tx.Creds) - 1
	authCred := tx.Creds[baseTxCredsLen]

	if err := fx.VerifyPermission(tx.Unsigned, auth, authCred, owner); err != nil {
		return nil, fmt.Errorf("%w: %w", errUnauthorizedModification, err)
	}

	return tx.Creds[:baseTxCredsLen], nil
}
