// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2025, Lux Industries Inc All rights reserved.
// FALCON credential implementation for post-quantum signatures

package falconfx

import (
	"errors"

	"github.com/luxfi/vm/components/verify"
)

var (
	_ verify.Verifiable = (*FalconCredential)(nil)
)

// FalconSignature represents a single FALCON-512 signature
type FalconSignature struct {
	Salt [40]byte `serialize:"true" json:"salt"`
	Sig  []byte   `serialize:"true" json:"signature"`
}

// FalconCredential represents a credential that proves ownership using FALCON signatures
type FalconCredential struct {
	// For single signature
	Salt [40]byte `serialize:"true" json:"salt"`
	Sig  []byte   `serialize:"true" json:"signature"`

	// For multisig (threshold signatures)
	Sigs []FalconSignature `serialize:"true" json:"signatures"`
}

// Verify ensures the FalconCredential is well-formed
func (c *FalconCredential) Verify() error {
	// Single signature mode
	if len(c.Sig) > 0 {
		if len(c.Sig) > Falcon512SigMaxLen {
			return errors.New("FALCON signature too long")
		}
		return nil
	}

	// Multisig mode
	if len(c.Sigs) == 0 {
		return errors.New("no signatures provided")
	}

	for _, sig := range c.Sigs {
		if len(sig.Sig) > Falcon512SigMaxLen {
			return errors.New("FALCON signature too long in multisig")
		}
	}

	return nil
}

// FalconOutputOwners specifies who can spend an output using FALCON signatures
type FalconOutputOwners struct {
	Locktime  uint64 `serialize:"true" json:"locktime"`
	Threshold uint32 `serialize:"true" json:"threshold"`

	// Single public key for simple ownership
	FalconPublicKey []byte `serialize:"true" json:"falconPublicKey"`

	// Multiple public keys for threshold multisig
	FalconPublicKeys [][]byte `serialize:"true" json:"falconPublicKeys"`
}

// Verify ensures the FalconOutputOwners is well-formed
func (o *FalconOutputOwners) Verify() error {
	// Single owner mode
	if len(o.FalconPublicKey) > 0 {
		if len(o.FalconPublicKey) != Falcon512PublicLen {
			return ErrInvalidFalconPublicKey
		}
		if o.Threshold != 1 {
			return errors.New("threshold must be 1 for single owner")
		}
		return nil
	}

	// Multisig mode
	if len(o.FalconPublicKeys) == 0 {
		return errors.New("no public keys provided")
	}

	if o.Threshold == 0 || o.Threshold > uint32(len(o.FalconPublicKeys)) {
		return errors.New("invalid threshold")
	}

	for _, pk := range o.FalconPublicKeys {
		if len(pk) != Falcon512PublicLen {
			return ErrInvalidFalconPublicKey
		}
	}

	return nil
}

// Addresses returns the addresses that can spend this output
// For FALCON, we derive addresses from public keys
func (o *FalconOutputOwners) Addresses() [][]byte {
	// This is a simplified version - actual implementation would
	// derive proper addresses from FALCON public keys
	if len(o.FalconPublicKey) > 0 {
		return [][]byte{deriveAddressFromFalconPubKey(o.FalconPublicKey)}
	}

	addrs := make([][]byte, len(o.FalconPublicKeys))
	for i, pk := range o.FalconPublicKeys {
		addrs[i] = deriveAddressFromFalconPubKey(pk)
	}
	return addrs
}

// deriveAddressFromFalconPubKey derives an address from a FALCON public key
func deriveAddressFromFalconPubKey(pubKey []byte) []byte {
	// This could use a hash of the public key similar to Bitcoin
	return pubKey[:20] // Placeholder
}
