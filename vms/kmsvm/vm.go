// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package kmsvm implements the KMS Virtual Machine (K-Chain) for distributed
// key management using ML-KEM post-quantum cryptography and threshold sharing.
package kmsvm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/rpc/v2"

	"github.com/luxfi/cache"
	consensuscore "github.com/luxfi/consensus/core"
	consensusinterfaces "github.com/luxfi/consensus/core/interfaces"
	"github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/database"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/timer/mockable"
	"github.com/luxfi/utils/json"
	"github.com/luxfi/version"
	"github.com/luxfi/vm/vms/kmsvm/config"
	"github.com/luxfi/warp"
)

const (
	// Version of the K-Chain VM
	Version = "1.0.0"

	// VMID is the unique identifier for K-Chain VM
	VMID = "kmsvm"

	// MaxParallelOperations is the maximum number of concurrent crypto operations
	MaxParallelOperations = 100

	// SharePrefix is the database prefix for key shares
	SharePrefix = "share:"

	// KeyPrefix is the database prefix for key metadata
	KeyPrefix = "key:"
)

var (
	errVMShutdown         = errors.New("VM is shutting down")
	errKeyNotFound        = errors.New("key not found")
	errKeyExists          = errors.New("key already exists")
	errInvalidThreshold   = errors.New("invalid threshold")
	errInsufficientShares = errors.New("insufficient shares for reconstruction")
	errInvalidSignature   = errors.New("invalid signature")
	errMLKEMNotEnabled    = errors.New("ML-KEM not enabled")
	errMLDSANotEnabled    = errors.New("ML-DSA not enabled")
	errValidatorNotFound  = errors.New("validator not found")
)

// KeyMetadata stores information about a distributed key.
type KeyMetadata struct {
	ID          ids.ID            `json:"id"`
	Name        string            `json:"name"`
	Algorithm   string            `json:"algorithm"`
	KeyType     string            `json:"keyType"`
	PublicKey   []byte            `json:"publicKey"`
	Threshold   int               `json:"threshold"`
	TotalShares int               `json:"totalShares"`
	Validators  []string          `json:"validators"`
	CreatedAt   time.Time         `json:"createdAt"`
	UpdatedAt   time.Time         `json:"updatedAt"`
	Status      string            `json:"status"`
	Tags        []string          `json:"tags"`
	Metadata    map[string]string `json:"metadata"`
}

// KeyShare represents a share of a distributed key.
type KeyShare struct {
	KeyID       ids.ID `json:"keyId"`
	ShareIndex  int    `json:"shareIndex"`
	ShareData   []byte `json:"shareData"` // Encrypted share
	ValidatorID string `json:"validatorId"`
	Timestamp   int64  `json:"timestamp"`
}

// VM implements the K-Chain Virtual Machine.
type VM struct {
	config.Config

	// Core components
	ctx          context.Context
	cancel       context.CancelFunc
	log          log.Logger
	db           database.Database
	versiondb    *versiondb.Database
	blockchainID ids.ID
	networkID    uint32

	// Key management
	keys       map[ids.ID]*KeyMetadata
	keysByName map[string]ids.ID
	shares     map[ids.ID][]*KeyShare
	keysLock   sync.RWMutex

	// ML-KEM keys cache
	mlkemCache    *cache.LRU[ids.ID, *mlkem.PrivateKey]
	mlkemPubCache *cache.LRU[ids.ID, *mlkem.PublicKey]

	// Transaction pool
	pendingTxs []*Transaction
	txLock     sync.Mutex

	// State management
	state        database.Database
	lastAccepted ids.ID
	height       uint64

	// HTTP service
	rpcServer *rpc.Server

	// Lifecycle
	shuttingDown bool
	shutdownLock sync.RWMutex

	// Clock
	clock mockable.Clock
}

// Initialize initializes the K-Chain VM.
func (vm *VM) Initialize(
	ctx context.Context,
	chainCtx interface{},
	db database.Database,
	genesisBytes []byte,
	upgradeBytes []byte,
	configBytes []byte,
	toEngine chan<- consensuscore.Message,
	fxs []*consensuscore.Fx,
	appSender warp.Sender,
) error {
	vm.ctx, vm.cancel = context.WithCancel(ctx)
	vm.db = db
	vm.versiondb = versiondb.New(db)
	vm.state = vm.versiondb

	// Parse configuration
	cfg, err := config.ParseConfig(configBytes)
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}
	vm.Config = cfg

	// Validate configuration
	if err := vm.Config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Initialize maps
	vm.keys = make(map[ids.ID]*KeyMetadata)
	vm.keysByName = make(map[string]ids.ID)
	vm.shares = make(map[ids.ID][]*KeyShare)
	vm.pendingTxs = make([]*Transaction, 0)

	// Initialize caches
	vm.mlkemCache = cache.NewLRU[ids.ID, *mlkem.PrivateKey](vm.Config.ShareCacheSize)
	vm.mlkemPubCache = cache.NewLRU[ids.ID, *mlkem.PublicKey](vm.Config.ShareCacheSize)

	// Parse genesis if provided
	if len(genesisBytes) > 0 {
		if err := vm.parseGenesis(genesisBytes); err != nil {
			return fmt.Errorf("failed to parse genesis: %w", err)
		}
	}

	// Load existing keys from database
	if err := vm.loadKeys(); err != nil {
		vm.log.Warn("failed to load keys from database", "error", err)
	}

	// Initialize HTTP handlers
	if err := vm.initializeHTTPHandlers(); err != nil {
		return fmt.Errorf("failed to initialize HTTP handlers: %w", err)
	}

	vm.log.Info("KMS VM initialized",
		"version", Version,
		"mlkemEnabled", vm.Config.MLKEMEnabled,
		"mldsaEnabled", vm.Config.MLDSAEnabled,
		"threshold", vm.Config.DefaultThreshold,
		"totalShares", vm.Config.DefaultTotalShares,
	)

	return nil
}

// CreateKey creates a new distributed key.
func (vm *VM) CreateKey(ctx context.Context, name, algorithm string, threshold, totalShares int) (*KeyMetadata, error) {
	vm.keysLock.Lock()
	defer vm.keysLock.Unlock()

	// Check if key already exists
	if _, exists := vm.keysByName[name]; exists {
		return nil, errKeyExists
	}

	// Validate threshold
	if threshold <= 0 || totalShares <= 0 || threshold > totalShares {
		return nil, errInvalidThreshold
	}

	// Generate key ID
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}
	keyID, _ := ids.ToID(idBytes)

	// Create key based on algorithm
	var pubKey []byte
	var keyType string

	switch algorithm {
	case "ml-kem-512", "ml-kem-768", "ml-kem-1024":
		if !vm.Config.MLKEMEnabled {
			return nil, errMLKEMNotEnabled
		}
		// Determine mode based on algorithm
		var mode mlkem.Mode
		switch algorithm {
		case "ml-kem-512":
			mode = mlkem.MLKEM512
		case "ml-kem-768":
			mode = mlkem.MLKEM768
		case "ml-kem-1024":
			mode = mlkem.MLKEM1024
		}
		// Generate ML-KEM key pair
		mlkemPubKey, privKey, err := mlkem.GenerateKey(mode)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ML-KEM key: %w", err)
		}
		pubKey = mlkemPubKey.Bytes()
		keyType = "encryption"

		// Cache the key
		vm.mlkemCache.Put(keyID, privKey)
		vm.mlkemPubCache.Put(keyID, mlkemPubKey)

	case "ml-dsa-44", "ml-dsa-65", "ml-dsa-87":
		if !vm.Config.MLDSAEnabled {
			return nil, errMLDSANotEnabled
		}
		// ML-DSA key generation would go here
		keyType = "signing"
		pubKey = make([]byte, 32) // Placeholder

	case "bls-threshold":
		keyType = "threshold-signing"
		pubKey = make([]byte, 48) // Placeholder for BLS public key

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Create key metadata
	now := time.Now()
	meta := &KeyMetadata{
		ID:          keyID,
		Name:        name,
		Algorithm:   algorithm,
		KeyType:     keyType,
		PublicKey:   pubKey,
		Threshold:   threshold,
		TotalShares: totalShares,
		Validators:  vm.Config.Validators[:totalShares],
		CreatedAt:   now,
		UpdatedAt:   now,
		Status:      "active",
		Metadata:    make(map[string]string),
	}

	// Store key metadata
	vm.keys[keyID] = meta
	vm.keysByName[name] = keyID

	// Persist to database
	if err := vm.saveKeyMetadata(meta); err != nil {
		return nil, fmt.Errorf("failed to save key metadata: %w", err)
	}

	vm.log.Info("created new key",
		"keyID", keyID,
		"name", name,
		"algorithm", algorithm,
		"threshold", threshold,
		"totalShares", totalShares,
	)

	return meta, nil
}

// GetKey retrieves key metadata by ID.
func (vm *VM) GetKey(ctx context.Context, keyID ids.ID) (*KeyMetadata, error) {
	vm.keysLock.RLock()
	defer vm.keysLock.RUnlock()

	meta, exists := vm.keys[keyID]
	if !exists {
		return nil, errKeyNotFound
	}

	return meta, nil
}

// GetKeyByName retrieves key metadata by name.
func (vm *VM) GetKeyByName(ctx context.Context, name string) (*KeyMetadata, error) {
	vm.keysLock.RLock()
	defer vm.keysLock.RUnlock()

	keyID, exists := vm.keysByName[name]
	if !exists {
		return nil, errKeyNotFound
	}

	return vm.keys[keyID], nil
}

// ListKeys lists all keys.
func (vm *VM) ListKeys(ctx context.Context) ([]*KeyMetadata, error) {
	vm.keysLock.RLock()
	defer vm.keysLock.RUnlock()

	keys := make([]*KeyMetadata, 0, len(vm.keys))
	for _, meta := range vm.keys {
		keys = append(keys, meta)
	}

	return keys, nil
}

// DeleteKey deletes a key and its shares.
func (vm *VM) DeleteKey(ctx context.Context, keyID ids.ID) error {
	vm.keysLock.Lock()
	defer vm.keysLock.Unlock()

	meta, exists := vm.keys[keyID]
	if !exists {
		return errKeyNotFound
	}

	// Remove from maps
	delete(vm.keys, keyID)
	delete(vm.keysByName, meta.Name)
	delete(vm.shares, keyID)

	// Remove from caches
	vm.mlkemCache.Evict(keyID)
	vm.mlkemPubCache.Evict(keyID)

	// Delete from database
	if err := vm.deleteKeyFromDB(keyID); err != nil {
		vm.log.Warn("failed to delete key from database", "error", err)
	}

	vm.log.Info("deleted key", "keyID", keyID, "name", meta.Name)

	return nil
}

// Encrypt encrypts data using the key's ML-KEM public key.
func (vm *VM) Encrypt(ctx context.Context, keyID ids.ID, plaintext []byte) ([]byte, []byte, error) {
	vm.keysLock.RLock()
	meta, exists := vm.keys[keyID]
	vm.keysLock.RUnlock()

	if !exists {
		return nil, nil, errKeyNotFound
	}

	if meta.KeyType != "encryption" {
		return nil, nil, fmt.Errorf("key type %s does not support encryption", meta.KeyType)
	}

	// Get public key from cache
	pubKey, exists := vm.mlkemPubCache.Get(keyID)
	if !exists {
		return nil, nil, fmt.Errorf("public key not in cache")
	}

	// Encapsulate to get shared secret
	ciphertext, sharedSecret, err := pubKey.Encapsulate()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encapsulate: %w", err)
	}

	// Use AES-GCM for authenticated encryption
	// Derive a 32-byte key from the shared secret (use first 32 bytes or hash if needed)
	var key [32]byte
	if len(sharedSecret) >= 32 {
		copy(key[:], sharedSecret[:32])
	} else {
		// If shared secret is shorter, repeat it
		for i := range key {
			key[i] = sharedSecret[i%len(sharedSecret)]
		}
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	encrypted := gcm.Seal(nonce, nonce, plaintext, nil)

	return encrypted, ciphertext, nil
}

// BuildBlock builds a new block from pending transactions.
func (vm *VM) BuildBlock(ctx context.Context) (consensuscore.Block, error) {
	vm.shutdownLock.RLock()
	if vm.shuttingDown {
		vm.shutdownLock.RUnlock()
		return nil, errVMShutdown
	}
	vm.shutdownLock.RUnlock()

	vm.txLock.Lock()
	txs := vm.pendingTxs
	vm.pendingTxs = make([]*Transaction, 0)
	vm.txLock.Unlock()

	if len(txs) == 0 {
		return nil, errors.New("no pending transactions")
	}

	// Create block
	vm.height++
	blockData := make([]byte, 0, 100)
	blockData = append(blockData, vm.lastAccepted[:]...)
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, vm.height)
	blockData = append(blockData, heightBytes...)

	blockID, _ := ids.ToID(blockData)
	block := &Block{
		id:           blockID,
		parentID:     vm.lastAccepted,
		height:       vm.height,
		timestamp:    vm.clock.Time(),
		transactions: txs,
		vm:           vm,
	}

	vm.log.Debug("built block",
		"blockID", blockID,
		"height", vm.height,
		"txCount", len(txs),
	)

	return block, nil
}

// ParseBlock parses a block from bytes.
func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (consensuscore.Block, error) {
	// Parse block from bytes
	block := &Block{vm: vm}
	// TODO: Implement proper deserialization
	return block, nil
}

// GetBlock retrieves a block by ID.
func (vm *VM) GetBlock(ctx context.Context, blockID ids.ID) (consensuscore.Block, error) {
	blockBytes, err := vm.state.Get(blockID[:])
	if err != nil {
		return nil, fmt.Errorf("block not found: %w", err)
	}
	return vm.ParseBlock(ctx, blockBytes)
}

// SetState sets the VM state.
func (vm *VM) SetState(ctx context.Context, state consensusinterfaces.State) error {
	vm.log.Info("KMS VM state transition", "state", fmt.Sprintf("%v", state))
	return nil
}

// Shutdown shuts down the VM.
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.shutdownLock.Lock()
	vm.shuttingDown = true
	vm.shutdownLock.Unlock()

	vm.log.Info("shutting down KMS VM")

	// Cancel context
	if vm.cancel != nil {
		vm.cancel()
	}

	// Close database
	if vm.versiondb != nil {
		if err := vm.versiondb.Close(); err != nil {
			vm.log.Error("failed to close database", "error", err)
		}
	}

	vm.log.Info("KMS VM shutdown complete")
	return nil
}

// Version returns the VM version.
func (vm *VM) Version(ctx context.Context) (string, error) {
	return Version, nil
}

// Connected handles node connection events.
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *version.Application) error {
	vm.log.Debug("node connected", "nodeID", nodeID, "version", nodeVersion)
	return nil
}

// Disconnected handles node disconnection events.
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	vm.log.Debug("node disconnected", "nodeID", nodeID)
	return nil
}

// HealthCheck returns VM health status.
func (vm *VM) HealthCheck(ctx context.Context) (interface{}, error) {
	vm.shutdownLock.RLock()
	shuttingDown := vm.shuttingDown
	vm.shutdownLock.RUnlock()

	vm.keysLock.RLock()
	keyCount := len(vm.keys)
	vm.keysLock.RUnlock()

	return map[string]interface{}{
		"healthy":      !shuttingDown,
		"version":      Version,
		"mlkemEnabled": vm.Config.MLKEMEnabled,
		"mldsaEnabled": vm.Config.MLDSAEnabled,
		"keyCount":     keyCount,
		"validators":   len(vm.Config.Validators),
	}, nil
}

// CreateHandlers returns HTTP handlers for the VM.
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return map[string]http.Handler{
		"/rpc": vm.rpcServer,
	}, nil
}

// CreateStaticHandlers returns static HTTP handlers.
func (vm *VM) CreateStaticHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return nil, nil
}

// Helper methods

func (vm *VM) initializeHTTPHandlers() error {
	vm.rpcServer = rpc.NewServer()

	service := &Service{vm: vm}
	vm.rpcServer.RegisterCodec(json.NewCodec(), "application/json")
	vm.rpcServer.RegisterCodec(json.NewCodec(), "application/json;charset=UTF-8")
	return vm.rpcServer.RegisterService(service, "kchain")
}

func (vm *VM) parseGenesis(genesisBytes []byte) error {
	vm.log.Info("parsing genesis", "size", len(genesisBytes))
	return nil
}

func (vm *VM) loadKeys() error {
	// TODO: Implement loading keys from database
	return nil
}

func (vm *VM) saveKeyMetadata(meta *KeyMetadata) error {
	// TODO: Implement persisting key metadata to database
	return nil
}

func (vm *VM) deleteKeyFromDB(keyID ids.ID) error {
	// TODO: Implement deleting key from database
	return nil
}
