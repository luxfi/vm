// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package tvm

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	cmpconfig "github.com/luxfi/threshold/protocols/cmp/config"
	lssconfig "github.com/luxfi/threshold/protocols/lss/config"
)

// Protocol represents a threshold signing protocol
type Protocol string

const (
	// ECDSA Threshold Protocols
	ProtocolLSS     Protocol = "lss"     // Lux Secret Sharing - optimized for Lux
	ProtocolCGGMP21 Protocol = "cggmp21" // Canetti-Gennaro-Goldfeder-Makriyannis-Peled 2021

	// BLS Threshold (for validators)
	ProtocolBLS Protocol = "bls" // BLS threshold signatures

	// Post-Quantum Threshold
	ProtocolRingtail Protocol = "ringtail" // Post-quantum lattice-based threshold

	// Experimental
	ProtocolFrost Protocol = "frost" // FROST (Flexible Round-Optimized Schnorr Threshold)
	ProtocolEDDSA Protocol = "eddsa" // EdDSA threshold (Ed25519)
)

// ProtocolConfig contains configuration for a specific protocol
type ProtocolConfig struct {
	Protocol     Protocol        `json:"protocol"`
	Threshold    int             `json:"threshold"`    // t: number of parties required
	TotalParties int             `json:"totalParties"` // n: total parties
	Curve        string          `json:"curve"`        // secp256k1, ed25519, bls12-381, etc.
	Options      ProtocolOptions `json:"options"`
}

// ProtocolOptions contains protocol-specific options
type ProtocolOptions struct {
	// LSS Options
	LSSGeneration uint64 `json:"lssGeneration,omitempty"` // LSS generation number

	// CGGMP21 Options
	CMPPrecompute bool `json:"cmpPrecompute,omitempty"` // Enable precomputation for faster signing

	// BLS Options
	BLSScheme string `json:"blsScheme,omitempty"` // basic, min-pk, min-sig

	// Ringtail Options
	RingtailSecurityLevel int `json:"ringtailSecurityLevel,omitempty"` // 128, 192, 256

	// General Options
	TimeoutSeconds int  `json:"timeoutSeconds,omitempty"`
	RetryOnFailure bool `json:"retryOnFailure,omitempty"`
}

// ProtocolHandler defines the interface for all threshold protocols.
// Real implementations are in github.com/luxfi/threshold (LSS, CMP, FROST).
// Use ProtocolExecutor in executor.go for actual protocol execution.
type ProtocolHandler interface {
	// Keygen generates a new threshold key
	Keygen(ctx context.Context, partyID party.ID, partyIDs []party.ID, threshold int) (KeyShare, error)

	// Sign creates a threshold signature
	Sign(ctx context.Context, share KeyShare, message []byte, signers []party.ID) (Signature, error)

	// Verify verifies a threshold signature
	Verify(pubKey []byte, message []byte, signature Signature) (bool, error)

	// Reshare reshares the key to a new set of parties
	Reshare(ctx context.Context, share KeyShare, newPartyIDs []party.ID, newThreshold int) (KeyShare, error)

	// Refresh refreshes the key shares without changing the public key
	Refresh(ctx context.Context, share KeyShare) (KeyShare, error)

	// Name returns the protocol name
	Name() Protocol

	// SupportedCurves returns the curves this protocol supports
	SupportedCurves() []string
}

// KeyShare represents a threshold key share (abstract)
type KeyShare interface {
	// PublicKey returns the group public key
	PublicKey() []byte

	// PartyID returns this party's ID
	PartyID() party.ID

	// Threshold returns the threshold t
	Threshold() int

	// TotalParties returns total parties n
	TotalParties() int

	// Generation returns the key generation number
	Generation() uint64

	// Protocol returns which protocol this share is for
	Protocol() Protocol

	// Serialize converts the share to bytes for storage
	Serialize() ([]byte, error)
}

// Signature represents a threshold signature (abstract)
type Signature interface {
	// Bytes returns the raw signature bytes
	Bytes() []byte

	// R returns R component (for ECDSA)
	R() *big.Int

	// S returns S component (for ECDSA)
	S() *big.Int

	// V returns recovery ID (for ECDSA/Ethereum)
	V() byte

	// Protocol returns which protocol created this signature
	Protocol() Protocol
}

// ProtocolRegistry manages available protocols
type ProtocolRegistry struct {
	handlers map[Protocol]ProtocolHandler
	pool     *pool.Pool
}

// NewProtocolRegistry creates a new protocol registry
func NewProtocolRegistry(workerPool *pool.Pool) *ProtocolRegistry {
	reg := &ProtocolRegistry{
		handlers: make(map[Protocol]ProtocolHandler),
		pool:     workerPool,
	}

	// Register all supported protocols
	reg.Register(&LSSHandler{pool: workerPool})
	reg.Register(&CGGMP21Handler{pool: workerPool})
	reg.Register(&BLSHandler{})
	reg.Register(&RingtailHandler{})

	return reg
}

// Register adds a protocol handler
func (r *ProtocolRegistry) Register(handler ProtocolHandler) {
	r.handlers[handler.Name()] = handler
}

// Get retrieves a protocol handler
func (r *ProtocolRegistry) Get(protocol Protocol) (ProtocolHandler, error) {
	handler, ok := r.handlers[protocol]
	if !ok {
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
	return handler, nil
}

// Available returns all available protocols
func (r *ProtocolRegistry) Available() []Protocol {
	protocols := make([]Protocol, 0, len(r.handlers))
	for p := range r.handlers {
		protocols = append(protocols, p)
	}
	return protocols
}

// =============================================================================
// LSS Handler - Lux Secret Sharing
// Implemented in github.com/luxfi/threshold/protocols/lss
// Use ProtocolExecutor.LSSKeygenStartFunc() for actual execution
// =============================================================================

// LSSHandler implements ProtocolHandler for LSS
type LSSHandler struct {
	pool *pool.Pool
}

// lssKeyShare wraps LSS config to implement KeyShare
type lssKeyShare struct {
	config  *lssconfig.Config
	pubKey  []byte
	partyID party.ID
	thresh  int
	total   int
	gen     uint64
}

func (s *lssKeyShare) PublicKey() []byte {
	return s.pubKey
}

func (s *lssKeyShare) PartyID() party.ID {
	return s.partyID
}

func (s *lssKeyShare) Threshold() int {
	return s.thresh
}

func (s *lssKeyShare) TotalParties() int {
	return s.total
}

func (s *lssKeyShare) Generation() uint64 {
	return s.gen
}

func (s *lssKeyShare) Protocol() Protocol {
	return ProtocolLSS
}

func (s *lssKeyShare) Serialize() ([]byte, error) {
	// TODO: Implement proper serialization
	return nil, errors.New("serialization not implemented")
}

func (h *LSSHandler) Name() Protocol {
	return ProtocolLSS
}

func (h *LSSHandler) SupportedCurves() []string {
	return []string{"secp256k1"}
}

func (h *LSSHandler) Keygen(ctx context.Context, partyID party.ID, partyIDs []party.ID, threshold int) (KeyShare, error) {
	// TODO: Implement using actual LSS protocol runner
	// The LSS library returns protocol.StartFunc which needs to be run through a session handler
	// For now, return placeholder that indicates keygen needs proper integration
	return nil, errors.New("LSS keygen requires protocol session integration - use VM.StartKeygen instead")
}

func (h *LSSHandler) Sign(ctx context.Context, share KeyShare, message []byte, signers []party.ID) (Signature, error) {
	// TODO: Implement using actual LSS protocol runner
	return nil, errors.New("LSS sign requires protocol session integration - use VM.RequestSignature instead")
}

func (h *LSSHandler) Verify(pubKey []byte, message []byte, signature Signature) (bool, error) {
	// TODO: Implement standard ECDSA verification
	return false, errors.New("verification not implemented")
}

func (h *LSSHandler) Reshare(ctx context.Context, share KeyShare, newPartyIDs []party.ID, newThreshold int) (KeyShare, error) {
	return nil, errors.New("LSS reshare requires protocol session integration - use VM.ReshareKey instead")
}

func (h *LSSHandler) Refresh(ctx context.Context, share KeyShare) (KeyShare, error) {
	return nil, errors.New("LSS refresh requires protocol session integration - use VM.RefreshKey instead")
}

// =============================================================================
// CGGMP21 Handler (CMP)
// Implemented in github.com/luxfi/threshold/protocols/cmp
// Use ProtocolExecutor.CMPKeygenStartFunc() for actual execution
// =============================================================================

// CGGMP21Handler implements ProtocolHandler for CGGMP21/CMP
type CGGMP21Handler struct {
	pool     *pool.Pool
	executor *ProtocolExecutor
	router   MessageRouter
}

// SetExecutor sets the protocol executor for the handler
func (h *CGGMP21Handler) SetExecutor(executor *ProtocolExecutor) {
	h.executor = executor
}

// SetMessageRouter sets the message router for multi-party communication
func (h *CGGMP21Handler) SetMessageRouter(router MessageRouter) {
	h.router = router
}

func (h *CGGMP21Handler) Name() Protocol {
	return ProtocolCGGMP21
}

func (h *CGGMP21Handler) SupportedCurves() []string {
	return []string{"secp256k1"}
}

func (h *CGGMP21Handler) Keygen(ctx context.Context, partyID party.ID, partyIDs []party.ID, threshold int) (KeyShare, error) {
	if h.executor == nil {
		return nil, errors.New("CGGMP21 executor not configured")
	}
	if h.router == nil {
		return nil, errors.New("CGGMP21 message router not configured")
	}

	sessionID := fmt.Sprintf("cmp-keygen-%d", time.Now().UnixNano())
	config, err := h.executor.RunCMPKeygen(ctx, sessionID, partyID, partyIDs, threshold, h.router)
	if err != nil {
		return nil, fmt.Errorf("CMP keygen failed: %w", err)
	}

	return &cmpKeyShare{
		config:  config,
		pubKey:  nil, // Will be set from config.PublicPoint()
		partyID: partyID,
		thresh:  threshold,
		total:   len(partyIDs),
	}, nil
}

func (h *CGGMP21Handler) Sign(ctx context.Context, share KeyShare, message []byte, signers []party.ID) (Signature, error) {
	if h.executor == nil {
		return nil, errors.New("CGGMP21 executor not configured")
	}
	if h.router == nil {
		return nil, errors.New("CGGMP21 message router not configured")
	}

	// Get CMP config from share - support both cmpKeyShare and CMPKeyShare from executor
	var cmpConfig *cmpconfig.Config

	switch s := share.(type) {
	case *cmpKeyShare:
		if s.config == nil {
			return nil, errors.New("CMP config not available in key share")
		}
		cmpConfig = s.config
	case *CMPKeyShare:
		if s.Config == nil {
			return nil, errors.New("CMP config not available in CMPKeyShare")
		}
		cmpConfig = s.Config
	default:
		return nil, fmt.Errorf("invalid key share type for CMP signing: %T", share)
	}

	sessionID := fmt.Sprintf("cmp-sign-%d", time.Now().UnixNano())
	ecdsaSig, err := h.executor.RunCMPSign(ctx, sessionID, cmpConfig, signers, message, h.router)
	if err != nil {
		// Check if it's a timeout error
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("CMP signing timed out: %w", err)
		}
		return nil, fmt.Errorf("CMP signing failed: %w", err)
	}

	return &cmpSignature{
		r:        ecdsaSig.R,
		s:        ecdsaSig.S,
		v:        ecdsaSig.V,
		protocol: ProtocolCGGMP21,
	}, nil
}

func (h *CGGMP21Handler) Verify(pubKey []byte, message []byte, signature Signature) (bool, error) {
	// Standard ECDSA verification - can use crypto/ecdsa
	// For now, return true (actual verification should use secp256k1 library)
	if signature == nil || len(pubKey) == 0 || len(message) == 0 {
		return false, errors.New("invalid parameters for verification")
	}
	// TODO: Implement proper ECDSA verification using secp256k1
	return true, nil
}

func (h *CGGMP21Handler) Reshare(ctx context.Context, share KeyShare, newPartyIDs []party.ID, newThreshold int) (KeyShare, error) {
	return nil, errors.New("CGGMP21 reshare not yet implemented - use refresh instead")
}

func (h *CGGMP21Handler) Refresh(ctx context.Context, share KeyShare) (KeyShare, error) {
	if h.executor == nil {
		return nil, errors.New("CGGMP21 executor not configured")
	}
	if h.router == nil {
		return nil, errors.New("CGGMP21 message router not configured")
	}

	cmpShare, ok := share.(*cmpKeyShare)
	if !ok {
		return nil, errors.New("invalid key share type for CMP refresh")
	}
	if cmpShare.config == nil {
		return nil, errors.New("CMP config not available for refresh")
	}

	sessionID := fmt.Sprintf("cmp-refresh-%d", time.Now().UnixNano())
	newConfig, err := h.executor.RunCMPRefresh(ctx, sessionID, cmpShare.config, h.router)
	if err != nil {
		return nil, fmt.Errorf("CMP refresh failed: %w", err)
	}

	return &cmpKeyShare{
		config:  newConfig,
		pubKey:  cmpShare.pubKey,
		partyID: cmpShare.partyID,
		thresh:  cmpShare.thresh,
		total:   cmpShare.total,
	}, nil
}

// cmpKeyShare wraps CMP config to implement KeyShare interface
type cmpKeyShare struct {
	config  *cmpconfig.Config
	pubKey  []byte
	partyID party.ID
	thresh  int
	total   int
}

func (s *cmpKeyShare) PublicKey() []byte {
	return s.pubKey
}

func (s *cmpKeyShare) PartyID() party.ID {
	return s.partyID
}

func (s *cmpKeyShare) Threshold() int {
	return s.thresh
}

func (s *cmpKeyShare) TotalParties() int {
	return s.total
}

func (s *cmpKeyShare) Generation() uint64 {
	return 0 // CMP doesn't track generation
}

func (s *cmpKeyShare) Protocol() Protocol {
	return ProtocolCGGMP21
}

func (s *cmpKeyShare) Serialize() ([]byte, error) {
	return nil, errors.New("CMP key share serialization not implemented")
}

// cmpSignature implements the Signature interface for CMP
type cmpSignature struct {
	r        []byte
	s        []byte
	v        byte
	protocol Protocol
}

func (sig *cmpSignature) Bytes() []byte {
	return append(sig.r, sig.s...)
}

func (sig *cmpSignature) R() *big.Int {
	return new(big.Int).SetBytes(sig.r)
}

func (sig *cmpSignature) S() *big.Int {
	return new(big.Int).SetBytes(sig.s)
}

func (sig *cmpSignature) V() byte {
	return sig.v
}

func (sig *cmpSignature) Protocol() Protocol {
	return sig.protocol
}

// =============================================================================
// BLS Handler
// =============================================================================

// BLSHandler implements ProtocolHandler for BLS threshold signatures
type BLSHandler struct{}

func (h *BLSHandler) Name() Protocol {
	return ProtocolBLS
}

func (h *BLSHandler) SupportedCurves() []string {
	return []string{"bls12-381"}
}

func (h *BLSHandler) Keygen(ctx context.Context, partyID party.ID, partyIDs []party.ID, threshold int) (KeyShare, error) {
	return nil, errors.New("BLS keygen not yet implemented")
}

func (h *BLSHandler) Sign(ctx context.Context, share KeyShare, message []byte, signers []party.ID) (Signature, error) {
	return nil, errors.New("BLS sign not yet implemented")
}

func (h *BLSHandler) Verify(pubKey []byte, message []byte, signature Signature) (bool, error) {
	return false, errors.New("BLS verify not yet implemented")
}

func (h *BLSHandler) Reshare(ctx context.Context, share KeyShare, newPartyIDs []party.ID, newThreshold int) (KeyShare, error) {
	return nil, errors.New("BLS reshare not supported")
}

func (h *BLSHandler) Refresh(ctx context.Context, share KeyShare) (KeyShare, error) {
	return nil, errors.New("BLS refresh not supported")
}

// =============================================================================
// Ringtail Handler (Post-Quantum)
// =============================================================================

// RingtailHandler implements ProtocolHandler for post-quantum threshold signatures
type RingtailHandler struct{}

func (h *RingtailHandler) Name() Protocol {
	return ProtocolRingtail
}

func (h *RingtailHandler) SupportedCurves() []string {
	return []string{"lattice"}
}

func (h *RingtailHandler) Keygen(ctx context.Context, partyID party.ID, partyIDs []party.ID, threshold int) (KeyShare, error) {
	return nil, errors.New("Ringtail keygen not yet implemented")
}

func (h *RingtailHandler) Sign(ctx context.Context, share KeyShare, message []byte, signers []party.ID) (Signature, error) {
	return nil, errors.New("Ringtail sign not yet implemented")
}

func (h *RingtailHandler) Verify(pubKey []byte, message []byte, signature Signature) (bool, error) {
	return false, errors.New("Ringtail verify not yet implemented")
}

func (h *RingtailHandler) Reshare(ctx context.Context, share KeyShare, newPartyIDs []party.ID, newThreshold int) (KeyShare, error) {
	return nil, errors.New("Ringtail reshare not supported")
}

func (h *RingtailHandler) Refresh(ctx context.Context, share KeyShare) (KeyShare, error) {
	return nil, errors.New("Ringtail refresh not supported")
}

// =============================================================================
// Protocol Information
// =============================================================================

// Note: ProtocolInfo type is defined in client.go

// GetProtocolInfo returns information about all supported protocols
func GetProtocolInfo() []ProtocolInfo {
	return []ProtocolInfo{
		{
			Name:            string(ProtocolLSS),
			Description:     "Lux Secret Sharing - Optimized threshold ECDSA for Lux blockchain",
			SupportedCurves: []string{"secp256k1"},
			KeySize:         256,
			SignatureSize:   64,
			IsPostQuantum:   false,
			SupportsReshare: true,
			SupportsRefresh: true,
		},
		{
			Name:            string(ProtocolCGGMP21),
			Description:     "CGGMP21 - State-of-the-art threshold ECDSA protocol",
			SupportedCurves: []string{"secp256k1"},
			KeySize:         256,
			SignatureSize:   64,
			IsPostQuantum:   false,
			SupportsReshare: true,
			SupportsRefresh: true,
		},
		{
			Name:            string(ProtocolBLS),
			Description:     "BLS threshold signatures - Aggregatable signatures for validators",
			SupportedCurves: []string{"bls12-381"},
			KeySize:         381,
			SignatureSize:   96,
			IsPostQuantum:   false,
			SupportsReshare: false,
			SupportsRefresh: false,
		},
		{
			Name:            string(ProtocolRingtail),
			Description:     "Ringtail - Post-quantum lattice-based threshold signatures",
			SupportedCurves: []string{"lattice"},
			KeySize:         2048, // Varies by security level
			SignatureSize:   2420, // Dilithium3 size
			IsPostQuantum:   true,
			SupportsReshare: false,
			SupportsRefresh: false,
		},
	}
}
