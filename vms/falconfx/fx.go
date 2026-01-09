// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2025, Lux Industries Inc All rights reserved.
// Post-quantum cryptography support - FALCON signatures for X-Chain

package falconfx

import (
	"errors"

	"github.com/luxfi/log"
	"github.com/luxfi/crypto/hash"
)

const (
	defaultCacheSize = 256

	// FALCON-512 parameters
	Falcon512Degree    = 512
	Falcon512Modulus   = 12289
	Falcon512SaltLen   = 40
	Falcon512PublicLen = 897
	Falcon512SigMaxLen = 690
)

var (
	ErrWrongVMType                    = errors.New("wrong vm type")
	ErrWrongTxType                    = errors.New("wrong tx type")
	ErrWrongOpType                    = errors.New("wrong operation type")
	ErrWrongUTXOType                  = errors.New("wrong utxo type")
	ErrWrongInputType                 = errors.New("wrong input type")
	ErrWrongCredentialType            = errors.New("wrong credential type")
	ErrWrongOwnerType                 = errors.New("wrong owner type")
	ErrMismatchedAmounts              = errors.New("utxo amount and input amount are not equal")
	ErrWrongNumberOfUTXOs             = errors.New("wrong number of utxos for the operation")
	ErrTimelocked                     = errors.New("output is time locked")
	ErrTooManySigners                 = errors.New("input has more signers than expected")
	ErrTooFewSigners                  = errors.New("input has less signers than expected")
	ErrInputOutputIndexOutOfBounds    = errors.New("input referenced a nonexistent address in the output")
	ErrInputCredentialSignersMismatch = errors.New("input expected a different number of signers than provided in the credential")
	ErrWrongSig                       = errors.New("wrong signature")
	ErrInvalidFalconSignature         = errors.New("invalid FALCON signature")
	ErrInvalidFalconPublicKey         = errors.New("invalid FALCON public key")
)

// Add FalconInput type alias
type FalconInput = FalconTransferInput

// codecVersion is the current codec version
const codecVersion = 0

// FalconFx describes the FALCON-512 post-quantum signature feature extension
// This provides quantum-resistant signatures for X-Chain UTXOs
type FalconFx struct {
	VerifyCache  *VerifyCache
	VM           VM
	bootstrapped bool
}

// VerifyCache caches FALCON signature verifications
type VerifyCache struct {
	cache map[string]bool
	size  int
}

func NewVerifyCache(size int) *VerifyCache {
	return &VerifyCache{
		cache: make(map[string]bool, size),
		size:  size,
	}
}

func (fx *FalconFx) Initialize(vmIntf interface{}) error {
	if err := fx.InitializeVM(vmIntf); err != nil {
		return err
	}

	log.Debug("initializing FALCON fx")

	cache := NewVerifyCache(defaultCacheSize)
	fx.VerifyCache = cache

	c := fx.VM.CodecRegistry()
	err := errors.Join(
		c.RegisterType(&FalconTransferInput{}),
		c.RegisterType(&FalconMintOutput{}),
		c.RegisterType(&FalconTransferOutput{}),
		c.RegisterType(&FalconMintOperation{}),
		c.RegisterType(&FalconCredential{}),
	)
	if err != nil {
		return err
	}

	log.Info("FALCON fx initialized")
	return nil
}

func (fx *FalconFx) InitializeVM(vmIntf interface{}) error {
	vm, ok := vmIntf.(VM)
	if !ok {
		return ErrWrongVMType
	}
	fx.VM = vm
	return nil
}

func (*FalconFx) Bootstrapping() error {
	return nil
}

func (fx *FalconFx) Bootstrapped() error {
	fx.bootstrapped = true
	return nil
}

// VerifyPermission verifies that a FALCON signature proves ownership
func (fx *FalconFx) VerifyPermission(txIntf, inIntf, credIntf, ownerIntf interface{}) error {
	tx, ok := txIntf.(UnsignedTx)
	if !ok {
		return ErrWrongTxType
	}

	in, ok := inIntf.(*FalconInput)
	if !ok {
		return ErrWrongInputType
	}

	cred, ok := credIntf.(*FalconCredential)
	if !ok {
		return ErrWrongCredentialType
	}

	owner, ok := ownerIntf.(*FalconOutputOwners)
	if !ok {
		return ErrWrongOwnerType
	}

	if err := fx.verifyFalconSignature(tx, in, cred, owner); err != nil {
		return err
	}

	return fx.verifyMultisigFalcon(tx, owner, cred)
}

func (fx *FalconFx) verifyFalconSignature(tx UnsignedTx, in *FalconInput, cred *FalconCredential, owner *FalconOutputOwners) error {
	// Get the message to be signed (transaction hash)
	txBytes := tx.Bytes()
	txHash := hash.ComputeHash256(txBytes)

	// Check cache first
	cacheKey := string(txHash) + string(cred.Sig)
	if cached, ok := fx.VerifyCache.cache[cacheKey]; ok {
		if cached {
			return nil
		}
		return ErrInvalidFalconSignature
	}

	// Verify FALCON signature
	valid := verifyFalcon512(txHash, cred.Salt[:], cred.Sig, owner.FalconPublicKey)

	// Cache result
	fx.VerifyCache.cache[cacheKey] = valid

	if !valid {
		return ErrInvalidFalconSignature
	}

	return nil
}

func (fx *FalconFx) verifyMultisigFalcon(tx UnsignedTx, owner *FalconOutputOwners, cred *FalconCredential) error {
	// Check threshold requirements
	if len(cred.Sigs) < int(owner.Threshold) {
		return ErrTooFewSigners
	}

	// Verify each signature
	txBytes := tx.Bytes()
	txHash := hash.ComputeHash256(txBytes)

	validSigs := 0
	for i, sig := range cred.Sigs {
		if i >= len(owner.FalconPublicKeys) {
			break
		}

		if verifyFalcon512(txHash, sig.Salt[:], sig.Sig, owner.FalconPublicKeys[i]) {
			validSigs++
			if validSigs >= int(owner.Threshold) {
				return nil
			}
		}
	}

	if validSigs < int(owner.Threshold) {
		return ErrTooFewSigners
	}

	return nil
}

// Stub function - would be implemented by integrating actual FALCON library
func verifyFalcon512(hash, salt, sig, pubKey []byte) bool {
	// This would call the actual FALCON-512 verification
	return false
}
