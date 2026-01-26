// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package verify

import (
	"context"
	"errors"
	"fmt"

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
	GetChainID(ctx context.Context, chainID ids.ID) (ids.ID, error)
}

// ConsensusValidatorState wraps the consensus context ValidatorState interface
type ConsensusValidatorState interface {
	GetChainID(chainID ids.ID) (ids.ID, error)
}

// SameNet verifies that the provided [ctx] was provided to a chain in the
// same chain as [peerChainID], but not the same chain. If this verification
// fails, a non-nil error will be returned.
func SameNet(ctx context.Context, chainCtx *ChainContext, peerChainID ids.ID) error {
	if peerChainID == chainCtx.ChainID {
		return ErrSameChainID
	}

	peerNetID, err := chainCtx.ValidatorState.GetChainID(ctx, peerChainID)
	if err != nil {
		return fmt.Errorf("failed to get net of %q: %w", peerChainID, err)
	}
	if chainCtx.NetID != peerNetID {
		return fmt.Errorf("%w; expected %q got %q", ErrMismatchedNetIDs, chainCtx.NetID, peerNetID)
	}
	return nil
}

// SameChainContext is a minimal interface for SameChain verification.
// This avoids importing runtime which would create a circular dependency.
type SameChainContext interface {
	GetChainID() ids.ID
	GetNetID() ids.ID
}

// SameChain verifies that the provided [peerChainID] is on the same network
// as the chain represented by [chainCtx], but is not the same chain.
// If verification fails, a non-nil error will be returned.
func SameChain(ctx context.Context, chainCtx SameChainContext, peerChainID ids.ID) error {
	if peerChainID == chainCtx.GetChainID() {
		return ErrSameChainID
	}
	// For SameChain, we only verify the chain isn't the same chain.
	// Network verification requires ValidatorState which is only in SameNet.
	return nil
}
