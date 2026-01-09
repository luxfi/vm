// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"context"
	"errors"
	"time"

	ethcommon "github.com/luxfi/geth/common"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/utils/hashing"
)

var (
	// Comment out interface check until Block is fully implemented
	// _ block.Block = (*Block)(nil)

	errInvalidBlock = errors.New("invalid block")
)

// Block represents a block in the ZK Chain
type Block struct {
	vm *VM

	id        ids.ID
	parentID  ids.ID
	height    uint64
	timestamp time.Time

	// ZK-specific block data
	challenges     []*ChallengeUpdate
	zkProofs       []*ZKProof
	fraudProofs    []*FraudProof
	privacyActions []*PrivacyAction

	status choices.Status
	bytes  []byte
}

// ChallengeUpdate represents an update to a challenge
type ChallengeUpdate struct {
	ChallengeID   ids.ID          `json:"challengeId"`
	NewStatus     ChallengeStatus `json:"newStatus"`
	DefenderProof []byte          `json:"defenderProof,omitempty"`
	Resolution    []byte          `json:"resolution,omitempty"`
}

// PrivacyAction represents a privacy-related action
type PrivacyAction struct {
	Type       PrivacyActionType `json:"type"`
	Commitment ethcommon.Hash    `json:"commitment,omitempty"`
	Nullifier  ethcommon.Hash    `json:"nullifier,omitempty"`
	Amount     uint64            `json:"amount,omitempty"`
	Proof      []byte            `json:"proof"`
}

// PrivacyActionType represents the type of privacy action
type PrivacyActionType uint8

const (
	Shield PrivacyActionType = iota
	Unshield
	Transfer
)

// ID implements the chain.Block interface
func (b *Block) ID() ids.ID {
	return b.id
}

// Accept implements the chain.Block interface
func (b *Block) Accept(context.Context) error {
	b.status = choices.Accepted

	// Process challenge updates
	b.vm.challengeMu.Lock()
	for _, update := range b.challenges {
		if challenge, exists := b.vm.challenges[update.ChallengeID]; exists {
			challenge.Status = update.NewStatus
			if update.DefenderProof != nil {
				challenge.DefenderProof = update.DefenderProof
			}
			if update.Resolution != nil {
				challenge.Resolution = update.Resolution
				challenge.ResolvedAt = b.timestamp.Unix()
			}
		}
	}
	b.vm.challengeMu.Unlock()

	// Process ZK proofs
	b.vm.proofMu.Lock()
	for _, proof := range b.zkProofs {
		proof.SubmittedAt = b.timestamp.Unix()
		b.vm.proofRegistry[proof.ID] = proof
	}
	b.vm.proofMu.Unlock()

	// Process fraud proofs
	for _, fraudProof := range b.fraudProofs {
		b.vm.fraudProofs[fraudProof.ID] = fraudProof
	}

	// Process privacy actions
	for _, action := range b.privacyActions {
		switch action.Type {
		case Shield:
			b.vm.shieldedPool.TotalSupply += action.Amount
			b.vm.shieldedPool.Commitments = append(b.vm.shieldedPool.Commitments, action.Commitment)
			b.vm.shieldedPool.Notes[action.Commitment] = true
		case Unshield:
			if b.vm.nullifierSet[action.Nullifier] {
				// Double spend attempt - should have been caught in Verify
				continue
			}
			b.vm.nullifierSet[action.Nullifier] = true
			b.vm.shieldedPool.TotalSupply -= action.Amount
		case Transfer:
			// Privacy-preserving transfer within the shielded pool
			if b.vm.nullifierSet[action.Nullifier] {
				continue
			}
			b.vm.nullifierSet[action.Nullifier] = true
			b.vm.shieldedPool.Commitments = append(b.vm.shieldedPool.Commitments, action.Commitment)
			b.vm.shieldedPool.Notes[action.Commitment] = true
		}
	}

	// Update last accepted
	b.vm.preferredID = b.id

	return nil
}

// Reject implements the chain.Block interface
func (b *Block) Reject(context.Context) error {
	b.status = choices.Rejected
	return nil
}

// Status implements the chain.Block interface
func (b *Block) Status() choices.Status {
	return b.status
}

// Parent implements the chain.Block interface
func (b *Block) Parent() ids.ID {
	return b.parentID
}

// ParentID returns the parent block ID (alias for Parent, required by block.Block interface)
func (b *Block) ParentID() ids.ID {
	return b.parentID
}

// Height implements the chain.Block interface
func (b *Block) Height() uint64 {
	return b.height
}

// Timestamp implements the chain.Block interface
func (b *Block) Timestamp() time.Time {
	return b.timestamp
}

// Verify implements the chain.Block interface
func (b *Block) Verify(ctx context.Context) error {
	// Verify block structure
	if b.height == 0 && b.parentID != ids.Empty {
		return errInvalidBlock
	}

	// Verify challenges
	for _, update := range b.challenges {
		if _, exists := b.vm.challenges[update.ChallengeID]; !exists {
			return errors.New("update for unknown challenge")
		}
	}

	// Verify ZK proofs
	for _, proof := range b.zkProofs {
		if err := b.vm.VerifyZKProof(proof); err != nil {
			return err
		}
	}

	// Verify privacy actions
	for _, action := range b.privacyActions {
		switch action.Type {
		case Shield:
			if action.Amount == 0 {
				return errors.New("cannot shield zero amount")
			}
		case Unshield, Transfer:
			if b.vm.nullifierSet[action.Nullifier] {
				return errors.New("double spend detected")
			}
			// TODO: Verify the ZK proof for the action
		}
	}

	b.status = choices.Processing
	return nil
}

// Bytes implements the chain.Block interface
func (b *Block) Bytes() []byte {
	if b.bytes == nil {
		// TODO: Implement proper serialization
		b.bytes = hashing.ComputeHash256([]byte(b.id.String()))
	}
	return b.bytes
}
