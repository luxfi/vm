// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package fee defines the unified FeePolicy interface that every Lux VM
// accepting user-submitted transactions MUST satisfy.
//
// Background. A 2026-05 audit of vms/* found five chains accepting user
// txs while charging nothing (dexvm, bridgevm, keyvm, zkvm, aivm) and one
// charging 1,000x too little (quantumvm). The root cause was that fee
// policy lived as ad-hoc fields on each VM's Config — there was no shared
// surface to enforce a non-zero floor, and no sentinel for chains that
// legitimately accept no user txs (mpcvm, oraclevm, relayvm —
// committee-driven, no user mempool).
//
// This package provides exactly one way to declare a fee policy:
//
//   - vms.Policy is the interface every VM Manager calls into.
//   - FlatPolicy is the canonical implementation for "burn a fixed
//     amount of LUX per tx".
//   - NoUserTxPolicy is the explicit sentinel for committee-only chains.
//     Manager wiring uses this to distinguish "explicitly no user fees"
//     from "forgot to set policy".
//   - Validate(p) is the boot-time check Manager runs against each VM's
//     declared policy to refuse zero-fee user-facing chains before they
//     ever accept a block.
//
// Migration plan (per audit follow-up): each offending VM declares a
// FlatPolicy in its Config, the VM's mempool calls Policy.ValidateFee at
// the same point it currently does (or fails to do) the fee check, and
// Manager runs Validate at chain bootstrap. No new abstraction layers,
// no per-VM bespoke fee structs — one interface, one validator.
package fee

import (
	"errors"

	"github.com/luxfi/ids"
)

// MinTxFeeFloor is the minimum tx fee, in µLUX (also called µLUX — 1e-6
// LUX), that any user-facing chain SHOULD charge. Matches the P-Chain
// base fee (utils/units: 1 mLUX = 1_000_000 µLUX). Used as the lower
// bound when reviewing/upgrading per-VM policies; not enforced inside
// Validate (a VM is free to charge MORE), but every VM choosing less
// will be flagged by the migration checklist.
//
// Known intentional exception: the X-Chain (xvm) prices transactions through
// its own UTXO fee subsystem (xvm/config.go TxFee, default 1000 µLUX), NOT the
// FlatPolicy here, and is deliberately outside this floor — its high-throughput
// UTXO economics are set independently of the account-model FlatPolicy floor.
// This is by design, not a migration miss; do not "fix" it by raising xvm
// TxFee to MinTxFeeFloor.
const MinTxFeeFloor uint64 = 1_000_000

// Sentinel errors returned by Policy implementations.
var (
	// ErrZeroMinFee is returned by Validate when a non-sentinel policy
	// declares a zero minimum fee. User-facing chains MUST charge > 0.
	ErrZeroMinFee = errors.New("fee policy declares zero min tx fee on a user-facing chain")

	// ErrWrongFeeAsset is returned by Policy.ValidateFee when the tx
	// pays in an asset other than the policy's FeeAssetID.
	ErrWrongFeeAsset = errors.New("tx pays fee in wrong asset")

	// ErrInsufficientFee is returned by Policy.ValidateFee when the
	// paid amount is below MinTxFee.
	ErrInsufficientFee = errors.New("tx fee below policy minimum")

	// ErrChainAcceptsNoUserTxs is returned by NoUserTxPolicy.ValidateFee
	// for any tx — committee-driven chains have no user mempool, so any
	// arrival at the fee gate is a wiring bug.
	ErrChainAcceptsNoUserTxs = errors.New("chain accepts no user-submitted txs")
)

// Policy defines how a VM charges for user-submitted txs. Every chain
// that accepts user txs MUST declare a non-nil Policy whose MinTxFee()
// returns a value > 0. Chains that accept no user txs declare a
// NoUserTxPolicy sentinel instead — this is the only legal way to opt
// out of charging.
type Policy interface {
	// MinTxFee returns the minimum fee, in µLUX, that any user tx must
	// pay. MUST be > 0 for user-facing VMs.
	MinTxFee() uint64

	// FeeAssetID returns the asset ID used for fee payment. For
	// primary-network burn, this is constants.UTXOAssetIDFor(networkID).
	FeeAssetID() ids.ID

	// ValidateFee returns nil if the paid amount and asset satisfy the
	// policy. Returns ErrWrongFeeAsset, ErrInsufficientFee, or
	// ErrChainAcceptsNoUserTxs as appropriate.
	ValidateFee(paidMicroLux uint64, paidAsset ids.ID) error
}

// FlatPolicy charges a fixed fee per user tx. The canonical
// implementation for VMs without dynamic gas pricing — dexvm, bridgevm,
// keyvm, zkvm, aivm use this (quantumvm is NoUserTxPolicy per LP-0130 §6).
type FlatPolicy struct {
	// Fee is the per-tx burn amount, in µLUX. MUST be > 0.
	Fee uint64

	// AssetID is the fee asset. For primary-network burn, use
	// constants.UTXOAssetIDFor(networkID).
	AssetID ids.ID
}

// MinTxFee returns the flat fee.
func (p FlatPolicy) MinTxFee() uint64 { return p.Fee }

// FeeAssetID returns the configured fee asset.
func (p FlatPolicy) FeeAssetID() ids.ID { return p.AssetID }

// ValidateFee enforces the flat policy.
func (p FlatPolicy) ValidateFee(paid uint64, asset ids.ID) error {
	if asset != p.AssetID {
		return ErrWrongFeeAsset
	}
	if paid < p.Fee {
		return ErrInsufficientFee
	}
	return nil
}

// NoUserTxPolicy is the sentinel policy for chains that accept no
// user-submitted txs — committee-driven only (mpcvm, oraclevm,
// relayvm). Distinguishing this from "policy not set" is what makes
// Manager's boot-time Validate able to refuse zero-fee user-facing
// chains without false-positive-ing the committee chains.
type NoUserTxPolicy struct{}

// MinTxFee always returns 0 — there are no user txs to charge.
func (NoUserTxPolicy) MinTxFee() uint64 { return 0 }

// FeeAssetID returns ids.Empty — there is no fee asset.
func (NoUserTxPolicy) FeeAssetID() ids.ID { return ids.Empty }

// ValidateFee always returns ErrChainAcceptsNoUserTxs — any caller
// reaching this gate is a wiring bug.
func (NoUserTxPolicy) ValidateFee(uint64, ids.ID) error {
	return ErrChainAcceptsNoUserTxs
}

// Validate is the boot-time check Manager runs against each VM's
// declared Policy. Returns ErrZeroMinFee if a non-sentinel policy
// declares MinTxFee() == 0. Returns nil for NoUserTxPolicy regardless
// of fee (it's the explicit opt-out). Returns nil if MinTxFee > 0.
func Validate(p Policy) error {
	if _, ok := p.(NoUserTxPolicy); ok {
		return nil
	}
	if p.MinTxFee() == 0 {
		return ErrZeroMinFee
	}
	return nil
}
