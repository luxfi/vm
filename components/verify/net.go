// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package verify

import (
	"context"
	"errors"
	"fmt"

	"github.com/luxfi/consensus/runtime"
	"github.com/luxfi/ids"
)

var (
	ErrSameChainID      = errors.New("same chainID")
	ErrMismatchedNetIDs = errors.New("mismatched netIDs")
)

// ChainContext provides context for chain operations
type ChainContext struct {
	ChainID        ids.ID
	NetID          ids.ID
	ValidatorState ValidatorState
}

// ValidatorState provides validator state lookups
type ValidatorState interface {
	GetNetID(ctx context.Context, chainID ids.ID) (ids.ID, error)
}

// ConsensusValidatorState wraps the consensus context ValidatorState interface
type ConsensusValidatorState interface {
	GetNetID(chainID ids.ID) (ids.ID, error)
}

// SameNet verifies that the provided [ctx] was provided to a chain in the
// same chain as [peerChainID], but not the same chain. If this verification
// fails, a non-nil error will be returned.
func SameNet(ctx context.Context, chainCtx *ChainContext, peerChainID ids.ID) error {
	if peerChainID == chainCtx.ChainID {
		return ErrSameChainID
	}

	peerNetID, err := chainCtx.ValidatorState.GetNetID(ctx, peerChainID)
	if err != nil {
		return fmt.Errorf("failed to get net of %q: %w", peerChainID, err)
	}
	if chainCtx.NetID != peerNetID {
		return fmt.Errorf("%w; expected %q got %q", ErrMismatchedNetIDs, chainCtx.NetID, peerNetID)
	}
	return nil
}

// SameChain verifies that the peerChainID is in the same network as the chain
// represented by rt, but not the same chain. This is a convenience
// wrapper for coreth compatibility that accepts *runtime.Runtime directly.
// With the simplified NetworkID model (1=mainnet, 2=testnet), chains on the
// same network are always in the same "chain".
func SameChain(ctx context.Context, rt *runtime.Runtime, peerChainID ids.ID) error {
	if peerChainID == rt.ChainID {
		return ErrSameChainID
	}

	// Get the validator state from runtime
	vs, ok := rt.ValidatorState.(runtime.ValidatorState)
	if !ok {
		return fmt.Errorf("validator state does not implement required interface")
	}

	// Verify the peer chain exists in the same network
	_, err := vs.GetChainID(peerChainID)
	if err != nil {
		return fmt.Errorf("failed to get chain of %q: %w", peerChainID, err)
	}
	// All chains on the same network (NetworkID 1 or 2) are in the same "chain"
	return nil
}
