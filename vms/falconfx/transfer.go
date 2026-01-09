// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2025, Lux Industries Inc All rights reserved.
// FALCON transfer input and output types for post-quantum UTXO transactions

package falconfx

import (
	"errors"

	"github.com/luxfi/vm/components/verify"
)

var (
	_ verify.Verifiable = (*FalconTransferInput)(nil)
	_ verify.Verifiable = (*FalconTransferOutput)(nil)
	_ verify.Verifiable = (*FalconMintOutput)(nil)
)

// FalconTransferInput represents an input that spends a FALCON-protected UTXO
type FalconTransferInput struct {
	// Amt is the amount of asset this input consumes
	Amt uint64 `serialize:"true" json:"amount"`

	// Input specifies which UTXOs to consume
	Input `serialize:"true"`
}

// Amount returns the amount of asset this input consumes
func (i *FalconTransferInput) Amount() uint64 {
	return i.Amt
}

// Verify ensures the FalconTransferInput is well-formed
func (i *FalconTransferInput) Verify() error {
	if i.Amt == 0 {
		return errors.New("input amount must be positive")
	}
	return i.Input.Verify()
}

// FalconTransferOutput represents an output that can be spent with FALCON signatures
type FalconTransferOutput struct {
	// Amt is the amount of asset stored in this output
	Amt uint64 `serialize:"true" json:"amount"`

	// OutputOwners specifies who can spend this output
	FalconOutputOwners `serialize:"true"`
}

// Amount returns the amount of asset stored in this output
func (o *FalconTransferOutput) Amount() uint64 {
	return o.Amt
}

// Verify ensures the FalconTransferOutput is well-formed
func (o *FalconTransferOutput) Verify() error {
	if o.Amt == 0 {
		return errors.New("output amount must be positive")
	}
	return o.FalconOutputOwners.Verify()
}

// FalconMintOutput represents a mintable output protected by FALCON signatures
type FalconMintOutput struct {
	// OutputOwners specifies who can mint more of this asset
	FalconOutputOwners `serialize:"true"`
}

// Verify ensures the FalconMintOutput is well-formed
func (o *FalconMintOutput) Verify() error {
	return o.FalconOutputOwners.Verify()
}

// FalconMintOperation represents an operation to mint new assets
type FalconMintOperation struct {
	// MintInput specifies the mint output to consume
	MintInput `serialize:"true"`

	// MintOutput specifies the new mint output to create
	MintOutput FalconMintOutput `serialize:"true" json:"mintOutput"`

	// TransferOutput specifies the newly minted assets
	TransferOutput FalconTransferOutput `serialize:"true" json:"transferOutput"`
}

// Verify ensures the FalconMintOperation is well-formed
func (op *FalconMintOperation) Verify() error {
	if err := op.MintInput.Verify(); err != nil {
		return err
	}
	if err := op.MintOutput.Verify(); err != nil {
		return err
	}
	return op.TransferOutput.Verify()
}

// Input represents a reference to a UTXO
type Input struct {
	// SigIndices specifies which signatures to use from the credential
	SigIndices []uint32 `serialize:"true" json:"signatureIndices"`
}

// Verify ensures the Input is well-formed
func (i *Input) Verify() error {
	if len(i.SigIndices) == 0 {
		return errors.New("input must have at least one signature index")
	}

	// Check for duplicates
	seen := make(map[uint32]bool)
	for _, idx := range i.SigIndices {
		if seen[idx] {
			return errors.New("duplicate signature index")
		}
		seen[idx] = true
	}

	return nil
}

// MintInput represents a reference to a mint output
type MintInput struct {
	// SigIndices specifies which signatures to use from the credential
	SigIndices []uint32 `serialize:"true" json:"signatureIndices"`
}

// Verify ensures the MintInput is well-formed
func (i *MintInput) Verify() error {
	if len(i.SigIndices) == 0 {
		return errors.New("mint input must have at least one signature index")
	}

	// Check for duplicates
	seen := make(map[uint32]bool)
	for _, idx := range i.SigIndices {
		if seen[idx] {
			return errors.New("duplicate signature index in mint input")
		}
		seen[idx] = true
	}

	return nil
}

// UnsignedTx represents an unsigned transaction
type UnsignedTx interface {
	verify.Verifiable
	Bytes() []byte
}
