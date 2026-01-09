// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2025, Lux Industries Inc All rights reserved.
// Q-Chain Quantum Stamper for C-Chain Block Replay
// Implements Crystal-Dilithium (ML-DSA) and SPHINCS+ (SLH-DSA) for post-quantum security

package stamper

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luxfi/cache"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/log"
	"github.com/luxfi/vm/vms/quantumvm/quantum"
)

var (
	ErrStampingDisabled      = errors.New("quantum stamping disabled")
	ErrInvalidBlockHeight    = errors.New("invalid block height")
	ErrStampAlreadyExists    = errors.New("quantum stamp already exists")
	ErrStampVerificationFail = errors.New("quantum stamp verification failed")
	ErrQChainNotSynced       = errors.New("Q-chain not synchronized")
	ErrInvalidSignatureMode  = errors.New("invalid signature mode")
)

// QuantumStampMode defines the post-quantum signature algorithm
type QuantumStampMode uint8

const (
	StampModeMLDSA44 QuantumStampMode = 0 // Crystal-Dilithium Level 2 (fast, smaller)
	StampModeMLDSA65 QuantumStampMode = 1 // Crystal-Dilithium Level 3 (balanced)
	StampModeMLDSA87 QuantumStampMode = 2 // Crystal-Dilithium Level 5 (highest security)
	StampModeSLHDSA  QuantumStampMode = 3 // SPHINCS+ (stateless hash-based)
	StampModeHybrid  QuantumStampMode = 4 // Hybrid ML-DSA + SLH-DSA
)

// QuantumStamp represents a quantum-resistant stamp for a C-Chain block
type QuantumStamp struct {
	// Block identification
	CChainHeight uint64      `json:"cchainHeight"`
	CChainHash   common.Hash `json:"cchainHash"`
	QChainHeight uint64      `json:"qchainHeight"`
	QChainHash   common.Hash `json:"qchainHash"`

	// Quantum signature data
	Mode            QuantumStampMode `json:"mode"`
	Timestamp       time.Time        `json:"timestamp"`
	MLDSASignature  []byte           `json:"mldsaSignature,omitempty"`
	SLHDSASignature []byte           `json:"slhdsaSignature,omitempty"`
	PublicKeyML     []byte           `json:"publicKeyML,omitempty"`
	PublicKeySLH    []byte           `json:"publicKeySLH,omitempty"`

	// Metadata
	StateRoot    common.Hash `json:"stateRoot"`
	ReceiptsRoot common.Hash `json:"receiptsRoot"`
	LogsBloom    []byte      `json:"logsBloom"`
	GasUsed      uint64      `json:"gasUsed"`

	// Cross-chain proof
	MerkleProof []common.Hash `json:"merkleProof,omitempty"`
	Nonce       []byte        `json:"nonce"`
}

// QuantumStamper handles quantum stamping of C-Chain blocks
type QuantumStamper struct {
	log     log.Logger
	enabled atomic.Bool
	mode    QuantumStampMode

	// Quantum signers
	mldsaSigner   *MLDSASigner
	slhdsaSigner  *SLHDSASigner
	quantumSigner *quantum.QuantumSigner

	// Block tracking
	cchainHeight atomic.Uint64
	qchainHeight atomic.Uint64
	stampCache   *cache.LRU[common.Hash, *QuantumStamp]

	// Synchronization
	mu          sync.RWMutex
	stampQueue  chan *stampRequest
	verifyQueue chan *verifyRequest

	// Metrics
	stampsCreated  atomic.Uint64
	stampsVerified atomic.Uint64
	stampsFailed   atomic.Uint64
}

type stampRequest struct {
	block    *types.Block
	response chan *QuantumStamp
	err      chan error
}

type verifyRequest struct {
	stamp    *QuantumStamp
	block    *types.Block
	response chan bool
}

// MLDSASigner wraps ML-DSA operations
type MLDSASigner struct {
	mode    mldsa.Mode
	privKey *mldsa.PrivateKey
	pubKey  *mldsa.PublicKey
}

// SLHDSASigner wraps SLH-DSA operations
type SLHDSASigner struct {
	mode    slhdsa.Mode
	privKey *slhdsa.PrivateKey
	pubKey  *slhdsa.PublicKey
}

// NewQuantumStamper creates a new quantum stamper for C-Chain blocks
func NewQuantumStamper(log log.Logger, mode QuantumStampMode, cacheSize int) (*QuantumStamper, error) {
	qs := &QuantumStamper{
		log:         log,
		mode:        mode,
		stampCache:  &cache.LRU[common.Hash, *QuantumStamp]{Size: cacheSize},
		stampQueue:  make(chan *stampRequest, 100),
		verifyQueue: make(chan *verifyRequest, 100),
	}

	// Initialize quantum signers based on mode
	if err := qs.initializeSigners(); err != nil {
		return nil, fmt.Errorf("failed to initialize signers: %w", err)
	}

	// Initialize Ringtail quantum signer for additional security
	qs.quantumSigner = quantum.NewQuantumSigner(log, 1, 256, 5*time.Minute, cacheSize)

	// Start worker goroutines
	go qs.stampWorker()
	go qs.verifyWorker()

	qs.enabled.Store(true)
	log.Info("Quantum stamper initialized",
		"mode", mode,
		"cacheSize", cacheSize)

	return qs, nil
}

// initializeSigners creates the cryptographic signers based on mode
func (qs *QuantumStamper) initializeSigners() error {
	switch qs.mode {
	case StampModeMLDSA44:
		return qs.initMLDSA(mldsa.MLDSA44)
	case StampModeMLDSA65:
		return qs.initMLDSA(mldsa.MLDSA65)
	case StampModeMLDSA87:
		return qs.initMLDSA(mldsa.MLDSA87)
	case StampModeSLHDSA:
		return qs.initSLHDSA(slhdsa.SHA2_128f)
	case StampModeHybrid:
		if err := qs.initMLDSA(mldsa.MLDSA65); err != nil {
			return err
		}
		return qs.initSLHDSA(slhdsa.SHA2_128f)
	default:
		return ErrInvalidSignatureMode
	}
}

func (qs *QuantumStamper) initMLDSA(mode mldsa.Mode) error {
	priv, err := mldsa.GenerateKey(rand.Reader, mode)
	if err != nil {
		return fmt.Errorf("failed to generate ML-DSA key: %w", err)
	}

	qs.mldsaSigner = &MLDSASigner{
		mode:    mode,
		privKey: priv,
		pubKey:  priv.PublicKey,
	}

	qs.log.Info("ML-DSA signer initialized", "mode", mode)
	return nil
}

func (qs *QuantumStamper) initSLHDSA(mode slhdsa.Mode) error {
	priv, err := slhdsa.GenerateKey(rand.Reader, mode)
	if err != nil {
		return fmt.Errorf("failed to generate SLH-DSA key: %w", err)
	}

	qs.slhdsaSigner = &SLHDSASigner{
		mode:    mode,
		privKey: priv,
		pubKey:  priv.PublicKey,
	}

	qs.log.Info("SLH-DSA signer initialized", "mode", mode)
	return nil
}

// StampBlock creates a quantum stamp for a C-Chain block during replay
func (qs *QuantumStamper) StampBlock(block *types.Block) (*QuantumStamp, error) {
	if !qs.enabled.Load() {
		return nil, ErrStampingDisabled
	}

	// Check cache first
	blockHash := block.Hash()
	if cached, found := qs.stampCache.Get(blockHash); found {
		return cached, nil
	}

	// Create stamp request
	req := &stampRequest{
		block:    block,
		response: make(chan *QuantumStamp, 1),
		err:      make(chan error, 1),
	}

	select {
	case qs.stampQueue <- req:
		select {
		case stamp := <-req.response:
			return stamp, nil
		case err := <-req.err:
			return nil, err
		case <-time.After(30 * time.Second):
			return nil, errors.New("stamping timeout")
		}
	case <-time.After(5 * time.Second):
		return nil, errors.New("stamp queue full")
	}
}

// stampWorker processes stamp requests
func (qs *QuantumStamper) stampWorker() {
	for req := range qs.stampQueue {
		stamp, err := qs.createStamp(req.block)
		if err != nil {
			req.err <- err
		} else {
			req.response <- stamp
		}
	}
}

// createStamp creates the actual quantum stamp
func (qs *QuantumStamper) createStamp(block *types.Block) (*QuantumStamp, error) {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	blockHeight := block.NumberU64()
	blockHash := block.Hash()

	// Update C-Chain height
	qs.cchainHeight.Store(blockHeight)

	// Calculate Q-Chain height (synchronized with C-Chain)
	qHeight := qs.calculateQChainHeight(blockHeight)
	qs.qchainHeight.Store(qHeight)

	// Create stamp data
	stamp := &QuantumStamp{
		CChainHeight: blockHeight,
		CChainHash:   blockHash,
		QChainHeight: qHeight,
		Mode:         qs.mode,
		Timestamp:    time.Now(),
		StateRoot:    block.Root(),
		ReceiptsRoot: block.ReceiptHash(),
		GasUsed:      block.GasUsed(),
		Nonce:        generateNonce(),
	}

	// Set logs bloom (limited to 256 bytes for efficiency)
	bloomBytes := block.Bloom().Bytes()
	if len(bloomBytes) > 256 {
		stamp.LogsBloom = bloomBytes[:256]
	} else {
		stamp.LogsBloom = bloomBytes
	}

	// Generate Q-Chain block hash
	stamp.QChainHash = qs.generateQChainHash(stamp)

	// Create signatures based on mode
	signData := qs.prepareSignatureData(stamp)

	switch qs.mode {
	case StampModeMLDSA44, StampModeMLDSA65, StampModeMLDSA87:
		if err := qs.signWithMLDSA(stamp, signData); err != nil {
			return nil, err
		}
	case StampModeSLHDSA:
		if err := qs.signWithSLHDSA(stamp, signData); err != nil {
			return nil, err
		}
	case StampModeHybrid:
		if err := qs.signWithMLDSA(stamp, signData); err != nil {
			return nil, err
		}
		if err := qs.signWithSLHDSA(stamp, signData); err != nil {
			return nil, err
		}
	}

	// Cache the stamp
	qs.stampCache.Put(blockHash, stamp)
	qs.stampsCreated.Add(1)

	// Log progress every 1000 blocks
	if blockHeight%1000 == 0 {
		qs.log.Info("Quantum stamping progress",
			"cchainHeight", blockHeight,
			"qchainHeight", qHeight,
			"totalStamped", qs.stampsCreated.Load())
	}

	return stamp, nil
}

// calculateQChainHeight determines Q-Chain height based on C-Chain height
func (qs *QuantumStamper) calculateQChainHeight(cchainHeight uint64) uint64 {
	// Q-Chain maintains 1:1 correspondence with C-Chain during replay
	// But starts from block 1 (genesis is block 0)
	return cchainHeight + 1
}

// generateQChainHash creates a quantum-enhanced hash for Q-Chain block
func (qs *QuantumStamper) generateQChainHash(stamp *QuantumStamp) common.Hash {
	hasher := sha256.New()

	// Include C-Chain reference
	hasher.Write(stamp.CChainHash.Bytes())
	binary.Write(hasher, binary.BigEndian, stamp.CChainHeight)

	// Include Q-Chain data
	binary.Write(hasher, binary.BigEndian, stamp.QChainHeight)
	hasher.Write(stamp.StateRoot.Bytes())
	hasher.Write(stamp.ReceiptsRoot.Bytes())
	hasher.Write(stamp.Nonce)

	// Add timestamp for temporal ordering
	binary.Write(hasher, binary.BigEndian, stamp.Timestamp.UnixNano())

	sum := hasher.Sum(nil)
	return common.BytesToHash(sum)
}

// prepareSignatureData creates the data to be signed
func (qs *QuantumStamper) prepareSignatureData(stamp *QuantumStamp) []byte {
	data := make([]byte, 0, 512)

	// Core block data
	data = append(data, stamp.CChainHash.Bytes()...)
	data = append(data, stamp.QChainHash.Bytes()...)

	// Heights
	heightBytes := make([]byte, 16)
	binary.BigEndian.PutUint64(heightBytes[:8], stamp.CChainHeight)
	binary.BigEndian.PutUint64(heightBytes[8:], stamp.QChainHeight)
	data = append(data, heightBytes...)

	// State data
	data = append(data, stamp.StateRoot.Bytes()...)
	data = append(data, stamp.ReceiptsRoot.Bytes()...)

	// Gas and timestamp
	gasBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(gasBytes, stamp.GasUsed)
	data = append(data, gasBytes...)

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(stamp.Timestamp.UnixNano()))
	data = append(data, timestampBytes...)

	// Nonce for uniqueness
	data = append(data, stamp.Nonce...)

	return data
}

// signWithMLDSA signs data using Crystal-Dilithium
func (qs *QuantumStamper) signWithMLDSA(stamp *QuantumStamp, data []byte) error {
	if qs.mldsaSigner == nil {
		return errors.New("ML-DSA signer not initialized")
	}

	signature, err := qs.mldsaSigner.privKey.Sign(rand.Reader, data, nil)
	if err != nil {
		return fmt.Errorf("ML-DSA signing failed: %w", err)
	}

	stamp.MLDSASignature = signature
	stamp.PublicKeyML = qs.mldsaSigner.pubKey.Bytes()

	return nil
}

// signWithSLHDSA signs data using SPHINCS+
func (qs *QuantumStamper) signWithSLHDSA(stamp *QuantumStamp, data []byte) error {
	if qs.slhdsaSigner == nil {
		return errors.New("SLH-DSA signer not initialized")
	}

	signature, err := qs.slhdsaSigner.privKey.Sign(rand.Reader, data, nil)
	if err != nil {
		return fmt.Errorf("failed to sign with SLH-DSA: %w", err)
	}
	stamp.SLHDSASignature = signature
	stamp.PublicKeySLH = qs.slhdsaSigner.pubKey.Bytes()

	return nil
}

// VerifyStamp verifies a quantum stamp
func (qs *QuantumStamper) VerifyStamp(stamp *QuantumStamp, block *types.Block) bool {
	if !qs.enabled.Load() {
		return false
	}

	req := &verifyRequest{
		stamp:    stamp,
		block:    block,
		response: make(chan bool, 1),
	}

	select {
	case qs.verifyQueue <- req:
		select {
		case valid := <-req.response:
			return valid
		case <-time.After(10 * time.Second):
			return false
		}
	default:
		// Queue full, verify synchronously
		return qs.verifyStampSync(stamp, block)
	}
}

// verifyWorker processes verification requests
func (qs *QuantumStamper) verifyWorker() {
	for req := range qs.verifyQueue {
		valid := qs.verifyStampSync(req.stamp, req.block)
		req.response <- valid
	}
}

// verifyStampSync performs synchronous stamp verification
func (qs *QuantumStamper) verifyStampSync(stamp *QuantumStamp, block *types.Block) bool {
	// Verify block correspondence
	if stamp.CChainHeight != block.NumberU64() {
		return false
	}
	if stamp.CChainHash != block.Hash() {
		return false
	}

	// Verify state correspondence
	if stamp.StateRoot != block.Root() {
		return false
	}
	if stamp.ReceiptsRoot != block.ReceiptHash() {
		return false
	}
	if stamp.GasUsed != block.GasUsed() {
		return false
	}

	// Prepare signature data
	signData := qs.prepareSignatureData(stamp)

	// Verify signatures based on mode
	switch stamp.Mode {
	case StampModeMLDSA44, StampModeMLDSA65, StampModeMLDSA87:
		if !qs.verifyMLDSA(stamp, signData) {
			qs.stampsFailed.Add(1)
			return false
		}
	case StampModeSLHDSA:
		if !qs.verifySLHDSA(stamp, signData) {
			qs.stampsFailed.Add(1)
			return false
		}
	case StampModeHybrid:
		if !qs.verifyMLDSA(stamp, signData) || !qs.verifySLHDSA(stamp, signData) {
			qs.stampsFailed.Add(1)
			return false
		}
	default:
		return false
	}

	qs.stampsVerified.Add(1)
	return true
}

// verifyMLDSA verifies Crystal-Dilithium signature
func (qs *QuantumStamper) verifyMLDSA(stamp *QuantumStamp, data []byte) bool {
	if len(stamp.MLDSASignature) == 0 || len(stamp.PublicKeyML) == 0 {
		return false
	}

	// Recreate public key from bytes
	pubKey, err := mldsa.PublicKeyFromBytes(stamp.PublicKeyML, mldsa.MLDSA65)
	if err != nil {
		return false
	}

	return pubKey.Verify(data, stamp.MLDSASignature, nil)
}

// verifySLHDSA verifies SPHINCS+ signature
func (qs *QuantumStamper) verifySLHDSA(stamp *QuantumStamp, data []byte) bool {
	if len(stamp.SLHDSASignature) == 0 || len(stamp.PublicKeySLH) == 0 {
		return false
	}

	// Recreate public key from bytes
	pubKey, err := slhdsa.PublicKeyFromBytes(stamp.PublicKeySLH, slhdsa.SHA2_128f)
	if err != nil {
		return false
	}

	return pubKey.Verify(data, stamp.SLHDSASignature, nil)
}

// GetStampForBlock retrieves a stamp for a specific block
func (qs *QuantumStamper) GetStampForBlock(blockHash common.Hash) (*QuantumStamp, bool) {
	return qs.stampCache.Get(blockHash)
}

// GetCurrentHeights returns current C-Chain and Q-Chain heights
func (qs *QuantumStamper) GetCurrentHeights() (cchainHeight, qchainHeight uint64) {
	return qs.cchainHeight.Load(), qs.qchainHeight.Load()
}

// GetMetrics returns stamping metrics
func (qs *QuantumStamper) GetMetrics() map[string]uint64 {
	return map[string]uint64{
		"stamps_created":  qs.stampsCreated.Load(),
		"stamps_verified": qs.stampsVerified.Load(),
		"stamps_failed":   qs.stampsFailed.Load(),
		"cchain_height":   qs.cchainHeight.Load(),
		"qchain_height":   qs.qchainHeight.Load(),
	}
}

// Enable enables quantum stamping
func (qs *QuantumStamper) Enable() {
	qs.enabled.Store(true)
	qs.log.Info("Quantum stamping enabled")
}

// Disable disables quantum stamping
func (qs *QuantumStamper) Disable() {
	qs.enabled.Store(false)
	qs.log.Info("Quantum stamping disabled")
}

// Close cleanly shuts down the stamper
func (qs *QuantumStamper) Close() {
	qs.Disable()
	close(qs.stampQueue)
	close(qs.verifyQueue)
}

// Helper functions

func generateNonce() []byte {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	return nonce
}

// ExportStamps exports all stamps for persistence
func (qs *QuantumStamper) ExportStamps() map[common.Hash]*QuantumStamp {
	stamps := make(map[common.Hash]*QuantumStamp)
	// Note: This requires cache iteration which isn't directly supported
	// In production, maintain a separate map or database
	return stamps
}

// ImportStamps imports stamps from persistence
func (qs *QuantumStamper) ImportStamps(stamps map[common.Hash]*QuantumStamp) {
	for hash, stamp := range stamps {
		qs.stampCache.Put(hash, stamp)
	}
	qs.log.Info("Imported quantum stamps", "count", len(stamps))
}
