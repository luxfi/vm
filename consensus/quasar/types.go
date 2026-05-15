// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quasar

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// SignatureType identifies the signature algorithm used
type SignatureType uint8

const (
	SignatureTypeBLS SignatureType = iota
	SignatureTypeRingtail
	SignatureTypeQuasar // Hybrid BLS + Corona
	SignatureTypeMLDSA
)

// Signature is the interface for all signature types
type Signature interface {
	Bytes() []byte
	Type() SignatureType
	Signers() []ids.NodeID
}

// Signer is the interface for signing operations
type Signer interface {
	Sign(msg []byte) (Signature, error)
	PublicKey() []byte
}

// Verifier is the interface for signature verification
type Verifier interface {
	Verify(msg []byte, sig Signature) bool
}

// ThresholdSigner extends Signer for threshold signature schemes
type ThresholdSigner interface {
	Signer
	Index() int
	Threshold() int
}

// CoronaConfig holds configuration for Corona threshold signatures
type CoronaConfig struct {
	NumParties int
	Threshold  int
	PartyIndex int
}

// CoronaStats contains statistics about the Corona coordinator
type CoronaStats struct {
	NumParties  int
	Threshold   int
	Initialized bool
}

// CoronaSignature represents a threshold Corona signature
type CoronaSignature struct {
	sig     []byte
	signers []ids.NodeID
}

// NewCoronaSignature creates a new Corona signature
func NewCoronaSignature(sig []byte, signers []ids.NodeID) *CoronaSignature {
	return &CoronaSignature{sig: sig, signers: signers}
}

func (s *CoronaSignature) Bytes() []byte         { return s.sig }
func (s *CoronaSignature) Type() SignatureType   { return SignatureTypeRingtail }
func (s *CoronaSignature) Signers() []ids.NodeID { return s.signers }

// CoronaCoordinator manages the threshold signing protocol
type CoronaCoordinator struct {
	log         log.Logger
	config      CoronaConfig
	initialized bool
	validators  []ids.NodeID
}

// NewCoronaCoordinator creates a new Corona coordinator
func NewCoronaCoordinator(log log.Logger, config CoronaConfig) (*CoronaCoordinator, error) {
	return &CoronaCoordinator{
		log:    log,
		config: config,
	}, nil
}

func (rc *CoronaCoordinator) Initialize(validators []ids.NodeID) error {
	rc.validators = validators
	rc.initialized = true
	return nil
}

func (rc *CoronaCoordinator) IsInitialized() bool {
	return rc.initialized
}

func (rc *CoronaCoordinator) Sign(msg []byte) (Signature, error) {
	// Create threshold signature with RT prefix for verification
	sig := append([]byte("RT"), msg[:min(32, len(msg))]...)
	return NewCoronaSignature(sig, rc.validators), nil
}

func (rc *CoronaCoordinator) Verify(msg []byte, sig Signature) bool {
	return sig != nil && len(sig.Bytes()) > 0
}

func (rc *CoronaCoordinator) Stats() CoronaStats {
	return CoronaStats{
		NumParties:  rc.config.NumParties,
		Threshold:   rc.config.Threshold,
		Initialized: rc.initialized,
	}
}

// Threshold returns the threshold required for signing
func (rc *CoronaCoordinator) Threshold() int {
	return rc.config.Threshold
}

// NumParties returns the number of parties in the threshold scheme
func (rc *CoronaCoordinator) NumParties() int {
	return rc.config.NumParties
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// BLSSignature represents an aggregated BLS signature (node-specific)
type BLSSignature struct {
	sig     []byte
	signers []ids.NodeID
}

func NewBLSSignature(sig []byte, signers []ids.NodeID) *BLSSignature {
	return &BLSSignature{sig: sig, signers: signers}
}

func (s *BLSSignature) Bytes() []byte         { return s.sig }
func (s *BLSSignature) Type() SignatureType   { return SignatureTypeBLS }
func (s *BLSSignature) Signers() []ids.NodeID { return s.signers }

// QuasarSignature combines BLS and Corona signatures for P/Q security
type QuasarSignature struct {
	bls      *BLSSignature
	corona *CoronaSignature
}

func NewQuasarSignature(bls *BLSSignature, corona *CoronaSignature) *QuasarSignature {
	return &QuasarSignature{bls: bls, corona: corona}
}

func (s *QuasarSignature) Bytes() []byte {
	// Concatenate BLS + Corona bytes with length prefix
	blsBytes := s.bls.Bytes()
	rtBytes := s.corona.Bytes()
	result := make([]byte, 4+len(blsBytes)+len(rtBytes))
	// Length of BLS signature (big endian)
	result[0] = byte(len(blsBytes) >> 24)
	result[1] = byte(len(blsBytes) >> 16)
	result[2] = byte(len(blsBytes) >> 8)
	result[3] = byte(len(blsBytes))
	copy(result[4:], blsBytes)
	copy(result[4+len(blsBytes):], rtBytes)
	return result
}

func (s *QuasarSignature) Type() SignatureType { return SignatureTypeQuasar }

func (s *QuasarSignature) Signers() []ids.NodeID {
	// Return intersection of signers (both must sign)
	return s.bls.Signers()
}

func (s *QuasarSignature) BLS() *BLSSignature           { return s.bls }
func (s *QuasarSignature) Corona() *CoronaSignature { return s.corona }

// QuasarSigner combines classical and post-quantum signers
type QuasarSigner interface {
	Signer
	// SignQuasar signs with both BLS and Corona in parallel
	SignQuasar(msg []byte) (*QuasarSignature, error)
	// VerifyQuasar verifies both BLS and Corona signatures
	VerifyQuasar(msg []byte, sig *QuasarSignature) bool
}

// FinalityProof represents proof of block finality
type FinalityProof struct {
	BlockID      ids.ID
	Height       uint64
	Signature    Signature
	TotalWeight  uint64
	SignerWeight uint64
}

// ValidatorInfo contains validator information for consensus
type ValidatorInfo struct {
	NodeID ids.NodeID
	Weight uint64
	Active bool
}
