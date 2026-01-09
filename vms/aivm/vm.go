// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package aivm provides the AI Virtual Machine for the Lux network.
// AIVM handles AI compute tasks, provider attestation, and reward distribution.
//
// Key features:
//   - TEE attestation for compute providers (CPU: SGX/SEV-SNP/TDX, GPU: nvtrust)
//   - Local GPU attestation via nvtrust (no cloud dependency)
//   - Task submission and assignment
//   - Mining rewards and merkle anchoring to Q-Chain
package aivm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	consensusctx "github.com/luxfi/consensus/context"
	core "github.com/luxfi/consensus/core"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"

	"github.com/luxfi/version"

	"github.com/luxfi/ai/pkg/aivm"
	"github.com/luxfi/ai/pkg/attestation"
)

var (
	Version = &version.Semantic{
		Major: 1,
		Minor: 0,
		Patch: 0,
	}

	ErrNotInitialized   = errors.New("vm not initialized")
	ErrInvalidTask      = errors.New("invalid task")
	ErrProviderNotFound = errors.New("provider not found")
)

// Config contains AIVM configuration
type Config struct {
	// Network settings
	MaxProvidersPerNode int `serialize:"true" json:"maxProvidersPerNode"`
	MaxTasksPerProvider int `serialize:"true" json:"maxTasksPerProvider"`

	// Attestation settings
	RequireTEEAttestation bool   `serialize:"true" json:"requireTEEAttestation"`
	MinTrustScore         uint8  `serialize:"true" json:"minTrustScore"`
	AttestationTimeout    string `serialize:"true" json:"attestationTimeout"`

	// Task settings
	MaxTaskQueueSize int    `serialize:"true" json:"maxTaskQueueSize"`
	TaskTimeout      string `serialize:"true" json:"taskTimeout"`

	// Reward settings
	BaseReward       uint64 `serialize:"true" json:"baseReward"`
	EpochDuration    string `serialize:"true" json:"epochDuration"`
	MerkleAnchorFreq int    `serialize:"true" json:"merkleAnchorFreq"` // Blocks between Q-Chain anchors
}

// DefaultConfig returns default AIVM configuration
func DefaultConfig() Config {
	return Config{
		MaxProvidersPerNode:   100,
		MaxTasksPerProvider:   10,
		RequireTEEAttestation: true,
		MinTrustScore:         50,
		AttestationTimeout:    "30s",
		MaxTaskQueueSize:      1000,
		TaskTimeout:           "5m",
		BaseReward:            1000000000, // 1 LUX in wei
		EpochDuration:         "1h",
		MerkleAnchorFreq:      100,
	}
}

// VM implements the AI Virtual Machine
type VM struct {
	ctx    *consensusctx.Context
	config Config

	// Database
	db database.Database

	// Core AI VM from luxfi/ai package
	core *aivm.VM

	// Attestation verifier (local nvtrust - no cloud dependency)
	verifier *attestation.Verifier

	// Block management
	lastAcceptedID ids.ID
	lastAccepted   *Block
	pendingBlocks  map[ids.ID]*Block

	// Consensus
	toEngine chan<- core.Message

	// Logging
	log log.Logger

	mu      sync.RWMutex
	running bool
}

// Block represents an AIVM block
type Block struct {
	ID        ids.ID    `json:"id"`
	ParentID  ids.ID    `json:"parentID"`
	Height    uint64    `json:"height"`
	Timestamp time.Time `json:"timestamp"`

	// AI-specific data
	Tasks        []aivm.Task       `json:"tasks,omitempty"`
	Results      []aivm.TaskResult `json:"results,omitempty"`
	MerkleRoot   [32]byte          `json:"merkleRoot"`
	ProviderRegs []ProviderReg     `json:"providerRegs,omitempty"`

	bytes []byte
	vm    *VM
}

// ProviderReg represents a provider registration in a block
type ProviderReg struct {
	ProviderID     string                        `json:"providerId"`
	WalletAddress  string                        `json:"walletAddress"`
	Endpoint       string                        `json:"endpoint"`
	CPUAttestation *attestation.AttestationQuote `json:"cpuAttestation,omitempty"`
	GPUAttestation *attestation.GPUAttestation   `json:"gpuAttestation,omitempty"`
}

// Initialize initializes the VM
func (vm *VM) Initialize(
	ctx context.Context,
	chainCtx interface{},
	db interface{},
	genesisBytes []byte,
	upgradeBytes []byte,
	configBytes []byte,
	msgChan interface{},
	fxs []interface{},
	appSender interface{},
) error {
	// Type assertions
	var ok bool
	vm.ctx, ok = chainCtx.(*consensusctx.Context)
	if !ok {
		return errors.New("invalid chain context type")
	}

	vm.db, ok = db.(database.Database)
	if !ok {
		return errors.New("invalid database type")
	}

	if msgChan != nil {
		vm.toEngine, ok = msgChan.(chan<- core.Message)
		if !ok {
			if biChan, ok := msgChan.(chan core.Message); ok {
				vm.toEngine = biChan
			} else {
				return errors.New("invalid message channel type")
			}
		}
	}

	if logger, ok := vm.ctx.Log.(log.Logger); ok {
		vm.log = logger
	} else {
		return errors.New("invalid logger type")
	}

	vm.pendingBlocks = make(map[ids.ID]*Block)

	// Parse configuration
	if len(configBytes) > 0 {
		if err := json.Unmarshal(configBytes, &vm.config); err != nil {
			return fmt.Errorf("failed to parse config: %w", err)
		}
	} else {
		vm.config = DefaultConfig()
	}

	// Initialize core AI VM
	vm.core = aivm.NewVM()

	// Initialize attestation verifier (local nvtrust - no cloud dependency)
	vm.verifier = attestation.NewVerifier()

	// Start core VM
	if err := vm.core.Start(ctx); err != nil {
		return fmt.Errorf("failed to start core AI VM: %w", err)
	}

	vm.running = true
	vm.log.Info("AIVM initialized",
		"requireTEE", vm.config.RequireTEEAttestation,
		"minTrustScore", vm.config.MinTrustScore,
	)

	return nil
}

// Shutdown shuts down the VM
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running {
		return nil
	}

	vm.running = false

	if vm.core != nil {
		return vm.core.Stop()
	}

	return nil
}

// SetState sets the VM state
func (vm *VM) SetState(ctx context.Context, state interface{}) error {
	return nil
}

// CreateHandlers returns HTTP handlers
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return map[string]http.Handler{
		"/rpc": NewService(vm),
	}, nil
}

// Connected notifies the VM about connected nodes
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *version.Application) error {
	return nil
}

// Disconnected notifies the VM about disconnected nodes
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	return nil
}

// RegisterProvider registers a new AI compute provider
func (vm *VM) RegisterProvider(provider *aivm.Provider) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running {
		return ErrNotInitialized
	}

	// Verify attestation meets minimum trust score
	if vm.config.RequireTEEAttestation {
		if provider.GPUAttestation != nil {
			status, err := vm.verifier.VerifyGPUAttestation(provider.GPUAttestation)
			if err != nil {
				return fmt.Errorf("GPU attestation failed: %w", err)
			}
			if status.TrustScore < vm.config.MinTrustScore {
				return fmt.Errorf("trust score %d below minimum %d", status.TrustScore, vm.config.MinTrustScore)
			}
		}
	}

	return vm.core.RegisterProvider(provider)
}

// VerifyGPUAttestation verifies GPU attestation (local nvtrust - no cloud)
func (vm *VM) VerifyGPUAttestation(att *attestation.GPUAttestation) (*attestation.DeviceStatus, error) {
	if !vm.running {
		return nil, ErrNotInitialized
	}
	return vm.verifier.VerifyGPUAttestation(att)
}

// SubmitTask submits a new AI task
func (vm *VM) SubmitTask(task *aivm.Task) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running {
		return ErrNotInitialized
	}

	return vm.core.SubmitTask(task)
}

// GetTask returns a task by ID
func (vm *VM) GetTask(taskID string) (*aivm.Task, error) {
	if !vm.running {
		return nil, ErrNotInitialized
	}
	return vm.core.GetTask(taskID)
}

// SubmitResult submits a task result
func (vm *VM) SubmitResult(result *aivm.TaskResult) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running {
		return ErrNotInitialized
	}

	return vm.core.SubmitResult(result)
}

// GetProviders returns all registered providers
func (vm *VM) GetProviders() []*aivm.Provider {
	if !vm.running {
		return nil
	}
	return vm.core.GetProviders()
}

// GetModels returns available AI models
func (vm *VM) GetModels() []*aivm.ModelInfo {
	if !vm.running {
		return nil
	}
	return vm.core.GetModels()
}

// GetStats returns VM statistics
func (vm *VM) GetStats() map[string]interface{} {
	if !vm.running {
		return nil
	}
	return vm.core.GetStats()
}

// GetMerkleRoot returns merkle root for Q-Chain anchoring
func (vm *VM) GetMerkleRoot() [32]byte {
	if !vm.running {
		return [32]byte{}
	}
	return vm.core.GetMerkleRoot()
}

// ClaimRewards claims pending rewards for a provider
func (vm *VM) ClaimRewards(providerID string) (string, error) {
	if !vm.running {
		return "", ErrNotInitialized
	}
	return vm.core.ClaimRewards(providerID)
}

// GetRewardStats returns reward statistics for a provider
func (vm *VM) GetRewardStats(providerID string) (map[string]interface{}, error) {
	if !vm.running {
		return nil, ErrNotInitialized
	}
	return vm.core.GetRewardStats(providerID)
}
