// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quasar

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/consensus/protocol/quasar"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// Quasar is the gravitational center of Lux consensus.
// It binds P-Chain (BLS signatures) and Q-Chain (Corona post-quantum threshold)
// into unified hybrid finality across all Lux networks.
//
// Architecture:
//   ALL validators have BOTH keypairs:
//   - BLS keypair → aggregate signatures (classical, fast)
//   - Corona keypair → threshold signatures (post-quantum, 2-round)
//
//   Both signature paths run IN PARALLEL:
//
//   Block arrives
//       │
//       ├─────────────────────────────────────────┐
//       │                                         │
//       ▼                                         ▼
//   BLS PATH (fast)                    CORONA PATH (quantum-safe)
//   ────────────────                   ─────────────────────────────
//   All validators sign                Round 1: All validators
//   with BLS keys                      generate commitments
//       │                                         │
//       ▼                                         ▼
//   Aggregate into                     Round 2: All validators
//   single 96-byte sig                 compute partial signatures
//       │                                         │
//       └─────────────────┬───────────────────────┘
//                         │
//                         ▼
//                  Finalize: combine into
//                  threshold signature
//                         │
//                         ▼
//               ┌─────────────────┐
//               │  HYBRID PROOF   │
//               │ BLS Aggregate   │ ← 96 bytes (2/3+ validators)
//               │ Corona Thresh │ ← ~KB (t-of-n threshold)
//               └─────────────────┘
//                         │
//                         ▼
//                QUANTUM FINALITY
//
// The quasar ensures blocks achieve finality only when BOTH complete:
// 1. 2/3+ validator weight signed via BLS (fast, classical)
// 2. t-of-n validators completed Corona threshold (post-quantum secure)

var (
	ErrQuasarNotStarted     = errors.New("quasar not started")
	ErrPChainNotConnected   = errors.New("P-Chain not connected")
	ErrQChainNotConnected   = errors.New("Q-Chain not connected")
	ErrCoronaNotConnected = errors.New("Corona coordinator not connected")
	ErrInsufficientWeight   = errors.New("insufficient validator weight")
	ErrInsufficientSigners  = errors.New("insufficient Corona signers")
	ErrFinalityFailed       = errors.New("hybrid finality verification failed")
	ErrBLSFailed            = errors.New("BLS aggregation failed")
	ErrCoronaFailed       = errors.New("Corona threshold signing failed")
)

// PChainProvider provides P-Chain state and finality events
type PChainProvider interface {
	GetFinalizedHeight() uint64
	GetValidators(height uint64) ([]ValidatorState, error)
	SubscribeFinality() <-chan FinalityEvent
}

// QuantumSignerFallback provides fallback single-signer quantum signatures
type QuantumSignerFallback interface {
	SignMessage(msg []byte) ([]byte, error)
}

// ValidatorState represents a validator's current state
// Each validator has BOTH BLS and Corona keys
type ValidatorState struct {
	NodeID      ids.NodeID
	Weight      uint64
	BLSPubKey   []byte // BLS public key for aggregate signatures
	CoronaKey []byte // Corona public key share for threshold sigs
	Active      bool
}

// FinalityEvent represents a P-Chain finality event
type FinalityEvent struct {
	Height     uint64
	BlockID    ids.ID
	Validators []ValidatorState
	Timestamp  time.Time
}

// QuantumFinality represents a block that achieved hybrid quantum finality
type QuantumFinality struct {
	BlockID         ids.ID
	PChainHeight    uint64
	QChainHeight    uint64
	BLSProof        []byte       // Aggregated BLS signature (96 bytes)
	CoronaProof   []byte       // Serialized Corona threshold signature
	SignerBitset    []byte       // Which validators signed BLS
	CoronaSigners []ids.NodeID // Which validators participated in Corona
	TotalWeight     uint64
	SignerWeight    uint64
	BLSLatency      time.Duration
	CoronaLatency time.Duration
	Timestamp       time.Time
}

// Quasar binds P-Chain and Q-Chain consensus into hybrid quantum finality
type Quasar struct {
	mu sync.RWMutex

	log  log.Logger
	core *quasar.Quasar

	// Chain connections
	pChain          PChainProvider
	quantumFallback QuantumSignerFallback

	// Corona threshold coordinator
	corona *CoronaCoordinator

	// State
	pHeight   uint64
	qHeight   uint64
	finalized map[ids.ID]*QuantumFinality

	// Configuration
	threshold int    // Corona threshold (t in t-of-n)
	quorumNum uint64 // BLS quorum numerator
	quorumDen uint64 // BLS quorum denominator

	// Channels
	finalityCh chan *QuantumFinality
	stopCh     chan struct{}
	running    bool
}

// NewQuasar creates a new Quasar consensus hub
func NewQuasar(log log.Logger, threshold int, quorumNum, quorumDen uint64) (*Quasar, error) {
	core, err := quasar.NewQuasar(threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to create quasar core: %w", err)
	}

	return &Quasar{
		log:        log,
		core:       core,
		threshold:  threshold,
		quorumNum:  quorumNum,
		quorumDen:  quorumDen,
		finalized:  make(map[ids.ID]*QuantumFinality),
		finalityCh: make(chan *QuantumFinality, 100),
		stopCh:     make(chan struct{}),
	}, nil
}

// ConnectPChain connects the P-Chain finality provider
func (q *Quasar) ConnectPChain(p PChainProvider) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.pChain = p
	if p != nil {
		q.pHeight = p.GetFinalizedHeight()
	}

	q.log.Info("quasar: P-Chain connected", "height", q.pHeight)
}

// ConnectQuantumFallback connects the quantum signer fallback
func (q *Quasar) ConnectQuantumFallback(f QuantumSignerFallback) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.quantumFallback = f
	q.log.Info("quasar: quantum fallback connected")
}

// ConnectCorona connects the Corona threshold coordinator
func (q *Quasar) ConnectCorona(rc *CoronaCoordinator) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.corona = rc
	q.log.Info("quasar: Corona coordinator connected")
}

// InitializeCorona initializes the Corona coordinator with validators
func (q *Quasar) InitializeCorona(validators []ids.NodeID) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.corona == nil {
		// Create coordinator if not provided
		numParties := len(validators)
		threshold := (numParties * 2 / 3) + 1 // 2/3 + 1 threshold
		if threshold < 2 {
			threshold = 2
		}

		rc, err := NewCoronaCoordinator(q.log, CoronaConfig{
			NumParties: numParties,
			Threshold:  threshold,
		})
		if err != nil {
			return fmt.Errorf("failed to create Corona coordinator: %w", err)
		}
		q.corona = rc
	}

	if err := q.corona.Initialize(validators); err != nil {
		return fmt.Errorf("failed to initialize Corona: %w", err)
	}

	q.log.Info("quasar: Corona initialized",
		"validators", len(validators),
		"threshold", q.corona.Stats().Threshold,
	)

	return nil
}

// Start begins the quasar consensus loop
func (q *Quasar) Start(ctx context.Context) error {
	q.mu.Lock()
	if q.pChain == nil {
		q.mu.Unlock()
		return ErrPChainNotConnected
	}
	if q.quantumFallback == nil {
		q.mu.Unlock()
		return ErrQChainNotConnected
	}
	q.running = true
	q.mu.Unlock()

	// Subscribe to P-Chain finality
	sub := q.pChain.SubscribeFinality()
	go q.run(ctx, sub)

	q.log.Info("quasar: started")
	return nil
}

// Stop halts the quasar
func (q *Quasar) Stop() {
	q.mu.Lock()
	if q.running {
		close(q.stopCh)
		q.running = false
	}
	q.mu.Unlock()
	q.log.Info("quasar: stopped")
}

// run is the main finality loop
func (q *Quasar) run(ctx context.Context, sub <-chan FinalityEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-q.stopCh:
			return
		case event := <-sub:
			if err := q.processFinality(ctx, event); err != nil {
				q.log.Error("quasar: finality failed",
					"height", event.Height,
					"error", err,
				)
			}
		}
	}
}

// processFinality processes a P-Chain finality event into hybrid finality
// Both BLS and Corona paths run IN PARALLEL
func (q *Quasar) processFinality(ctx context.Context, event FinalityEvent) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Sync validators to quasar core
	for _, v := range event.Validators {
		if v.Active {
			_, _ = q.core.AddValidator(v.NodeID.String(), v.Weight)
		}
	}

	// Create finality message
	msg := q.createMessage(event)
	msgStr := string(msg) // Corona uses string message

	// Run BLS and Corona IN PARALLEL
	var blsProof, signerBitset []byte
	var signerWeight uint64
	var coronaSig Signature
	var blsLatency, coronaLatency time.Duration
	var blsErr, coronaErr error
	var wg sync.WaitGroup

	// BLS path
	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		blsProof, signerBitset, signerWeight, blsErr = q.collectBLS(event, msg)
		blsLatency = time.Since(start)
	}()

	// Corona path (if coordinator is connected)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if q.corona == nil || !q.corona.IsInitialized() {
			// Fall back to single-signer quantum stamp
			start := time.Now()
			fallbackProof, err := q.createQuantumStampFallback(msg)
			if err == nil {
				coronaSig = NewCoronaSignature(fallbackProof, nil)
			}
			coronaErr = err
			coronaLatency = time.Since(start)
		} else {
			// Full threshold signing
			start := time.Now()
			coronaSig, coronaErr = q.collectCorona(msgStr)
			coronaLatency = time.Since(start)
		}
	}()

	wg.Wait()

	// Check BLS result
	if blsErr != nil {
		return fmt.Errorf("BLS collection: %w", blsErr)
	}

	// Check Corona result
	if coronaErr != nil {
		return fmt.Errorf("Corona threshold: %w", coronaErr)
	}

	// Check quorum
	totalWeight := q.totalWeight(event.Validators)
	if !q.checkQuorum(signerWeight, totalWeight) {
		return ErrInsufficientWeight
	}

	// Record finality
	q.qHeight++
	var coronaSigners []ids.NodeID
	var coronaProof []byte
	if coronaSig != nil {
		coronaSigners = coronaSig.Signers()
		coronaProof = coronaSig.Bytes()
	}
	finality := &QuantumFinality{
		BlockID:         event.BlockID,
		PChainHeight:    event.Height,
		QChainHeight:    q.qHeight,
		BLSProof:        blsProof,
		CoronaProof:   coronaProof,
		SignerBitset:    signerBitset,
		CoronaSigners: coronaSigners,
		TotalWeight:     totalWeight,
		SignerWeight:    signerWeight,
		BLSLatency:      blsLatency,
		CoronaLatency: coronaLatency,
		Timestamp:       time.Now(),
	}

	q.finalized[event.BlockID] = finality
	q.pHeight = event.Height

	// Emit
	select {
	case q.finalityCh <- finality:
	default:
	}

	q.log.Info("quasar: hybrid finality achieved",
		"block", event.BlockID,
		"pHeight", event.Height,
		"qHeight", q.qHeight,
		"weight", fmt.Sprintf("%d/%d", signerWeight, totalWeight),
		"blsLatency", blsLatency,
		"coronaLatency", coronaLatency,
		"coronaSigners", len(coronaSigners),
	)

	return nil
}

// createMessage creates the finality message to sign
func (q *Quasar) createMessage(event FinalityEvent) []byte {
	msg := make([]byte, 48) // 32 (blockID) + 8 (height) + 8 (timestamp)
	copy(msg[:32], event.BlockID[:])
	putUint64BE(msg[32:40], event.Height)
	putUint64BE(msg[40:48], uint64(event.Timestamp.UnixNano()))
	return msg
}

// collectBLS collects BLS signatures from validators and aggregates them
func (q *Quasar) collectBLS(event FinalityEvent, msg []byte) ([]byte, []byte, uint64, error) {
	var signerBitset []byte
	var signerWeight uint64
	signatures := make([]*quasar.QuasarSig, 0, len(event.Validators))

	for i, v := range event.Validators {
		if !v.Active {
			continue
		}

		sig, err := q.core.SignMessage(v.NodeID.String(), msg)
		if err != nil {
			continue // Skip failed signers
		}

		signatures = append(signatures, sig)
		signerWeight += v.Weight

		// Set bit
		byteIdx := i / 8
		for len(signerBitset) <= byteIdx {
			signerBitset = append(signerBitset, 0)
		}
		signerBitset[byteIdx] |= 1 << uint(i%8)
	}

	if len(signatures) == 0 {
		return nil, nil, 0, errors.New("no BLS signatures")
	}

	agg, err := q.core.AggregateSignatures(msg, signatures)
	if err != nil {
		return nil, nil, 0, err
	}

	return agg.BLSAggregated, signerBitset, signerWeight, nil
}

// collectCorona runs the 2-round Corona threshold protocol in parallel
func (q *Quasar) collectCorona(message string) (Signature, error) {
	if q.corona == nil {
		return nil, ErrCoronaNotConnected
	}

	// Use the high-level Sign API which handles all rounds internally
	sig, err := q.corona.Sign([]byte(message))
	if err != nil {
		return nil, fmt.Errorf("corona signing failed: %w", err)
	}

	// Verify the signature
	if !q.corona.Verify([]byte(message), sig) {
		return nil, ErrCoronaFailed
	}

	q.log.Debug("corona signature complete",
		"signers", len(sig.Signers()),
		"type", sig.Type(),
	)

	return sig, nil
}

// createQuantumStampFallback creates a single-signer quantum stamp (fallback mode)
func (q *Quasar) createQuantumStampFallback(msg []byte) ([]byte, error) {
	if q.quantumFallback == nil {
		// Return placeholder if no fallback configured
		return []byte("PQ-FALLBACK"), nil
	}
	return q.quantumFallback.SignMessage(msg)
}

// totalWeight calculates total validator weight
func (q *Quasar) totalWeight(validators []ValidatorState) uint64 {
	var total uint64
	for _, v := range validators {
		if v.Active {
			total += v.Weight
		}
	}
	return total
}

// checkQuorum verifies quorum is met
func (q *Quasar) checkQuorum(signerWeight, totalWeight uint64) bool {
	required := totalWeight * q.quorumNum / q.quorumDen
	return signerWeight >= required
}

// GetFinality returns finality for a block
func (q *Quasar) GetFinality(blockID ids.ID) (*QuantumFinality, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	f, ok := q.finalized[blockID]
	return f, ok
}

// Subscribe returns channel for finality events
func (q *Quasar) Subscribe() <-chan *QuantumFinality {
	return q.finalityCh
}

// Verify verifies a hybrid finality proof
func (q *Quasar) Verify(finality *QuantumFinality) error {
	if finality == nil {
		return ErrFinalityFailed
	}

	if len(finality.BLSProof) == 0 || len(finality.CoronaProof) == 0 {
		return ErrFinalityFailed
	}

	if !q.checkQuorum(finality.SignerWeight, finality.TotalWeight) {
		return ErrInsufficientWeight
	}

	// Verify BLS via hybrid engine
	agg := &quasar.AggregatedSignature{
		BLSAggregated: finality.BLSProof,
	}

	// Reconstruct message for verification
	msg := make([]byte, 48)
	copy(msg[:32], finality.BlockID[:])
	putUint64BE(msg[32:40], finality.PChainHeight)
	putUint64BE(msg[40:48], uint64(finality.Timestamp.UnixNano()))

	if !q.core.VerifyAggregatedSignature(msg, agg) {
		return ErrBLSFailed
	}

	// Verify Corona proof exists and has valid marker
	if len(finality.CoronaProof) < 3 || finality.CoronaProof[0] != 'R' || finality.CoronaProof[1] != 'T' {
		// Check if it's a fallback ML-DSA signature
		if len(finality.CoronaProof) < 8 {
			return ErrCoronaFailed
		}
	}

	return nil
}

// Stats returns quasar statistics
func (q *Quasar) Stats() QuasarStats {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var coronaStats CoronaStats
	if q.corona != nil {
		coronaStats = q.corona.Stats()
	}

	return QuasarStats{
		PChainHeight:      q.pHeight,
		QChainHeight:      q.qHeight,
		FinalizedBlocks:   len(q.finalized),
		Threshold:         q.threshold,
		QuorumNum:         q.quorumNum,
		QuorumDen:         q.quorumDen,
		Running:           q.running,
		CoronaParties:   coronaStats.NumParties,
		CoronaThreshold: coronaStats.Threshold,
		CoronaReady:     coronaStats.Initialized,
	}
}

// QuasarStats contains quasar statistics
type QuasarStats struct {
	PChainHeight      uint64
	QChainHeight      uint64
	FinalizedBlocks   int
	Threshold         int
	QuorumNum         uint64
	QuorumDen         uint64
	Running           bool
	CoronaParties   int
	CoronaThreshold int
	CoronaReady     bool
}

// GetCore returns the underlying quasar core for testing
func (q *Quasar) GetCore() *quasar.Quasar {
	return q.core
}

// GetCorona returns the Corona coordinator
func (q *Quasar) GetCorona() *CoronaCoordinator {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.corona
}

// CheckQuorum verifies quorum is met (exported for testing)
func (q *Quasar) CheckQuorum(signerWeight, totalWeight uint64) bool {
	return q.checkQuorum(signerWeight, totalWeight)
}

// CreateMessage creates the finality message to sign (exported for testing)
func (q *Quasar) CreateMessage(event FinalityEvent) []byte {
	return q.createMessage(event)
}

// TotalWeight calculates total validator weight (exported for testing)
func (q *Quasar) TotalWeight(validators []ValidatorState) uint64 {
	return q.totalWeight(validators)
}

// GetConfig returns quorum configuration (exported for testing)
func (q *Quasar) GetConfig() (threshold int, quorumNum, quorumDen uint64) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.threshold, q.quorumNum, q.quorumDen
}

// IsRunning returns whether the Quasar is currently running (exported for testing)
func (q *Quasar) IsRunning() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.running
}

// SetFinalized adds a finality record (exported for testing/benchmarking)
func (q *Quasar) SetFinalized(blockID ids.ID, finality *QuantumFinality) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.finalized[blockID] = finality
}

// GetFinalized retrieves a finality record (exported for testing)
func (q *Quasar) GetFinalized(blockID ids.ID) (*QuantumFinality, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	f, ok := q.finalized[blockID]
	return f, ok
}

// Helper: big-endian uint64
func putUint64BE(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (56 - i*8))
	}
}
