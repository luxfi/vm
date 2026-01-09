// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zvm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	consensusctx "github.com/luxfi/consensus/context"
	core "github.com/luxfi/consensus/core"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

func TestVMInitialize(t *testing.T) {
	require := require.New(t)

	// Create test context
	ctx := context.Background()
	chainCtx := &consensusctx.Context{
		ChainID: ids.GenerateTestID(),
		Log:     log.NoLog{},
	}

	// Create test database
	db := memdb.New()

	// Create genesis
	genesis := &Genesis{
		Timestamp: 1607144400,
		InitialTxs: []*Transaction{
			{
				Type: TransactionTypeMint,
				Outputs: []*ShieldedOutput{
					{
						Commitment:      make([]byte, 32),
						EncryptedNote:   make([]byte, 256),
						EphemeralPubKey: make([]byte, 32),
						OutputProof:     make([]byte, 128),
					},
				},
				Proof: &ZKProof{
					ProofType:    "groth16",
					ProofData:    make([]byte, 256),
					PublicInputs: [][]byte{make([]byte, 32)},
				},
			},
		},
	}

	genesisBytes, err := Codec.Marshal(codecVersion, genesis)
	require.NoError(err)

	// Create config
	config := ZConfig{
		EnableConfidentialTransfers: true,
		EnablePrivateAddresses:      true,
		ProofSystem:                 "groth16",
		CircuitType:                 "transfer",
		EnableFHE:                   false,
		MaxUTXOsPerBlock:            100,
		ProofCacheSize:              1000,
	}

	configBytes, err := Codec.Marshal(codecVersion, config)
	require.NoError(err)

	// Create VM
	vm := &VM{}

	// Initialize VM
	toEngine := make(chan core.Message, 1)
	require.NoError(vm.Initialize(
		ctx,
		chainCtx,
		db,
		genesisBytes,
		nil, // upgradeBytes
		configBytes,
		toEngine, // msgChan
		nil,      // fxs
		nil,      // appSender
	))

	// Verify initialization
	require.NotNil(vm.utxoDB)
	require.NotNil(vm.nullifierDB)
	require.NotNil(vm.stateTree)
	require.NotNil(vm.proofVerifier)
	require.NotNil(vm.addressManager)
	require.NotNil(vm.mempool)

	// Test health check
	health, err := vm.HealthCheck(ctx)
	require.NoError(err)
	require.NotNil(health)

	// Shutdown
	require.NoError(vm.Shutdown(ctx))
}

func TestShieldedTransaction(t *testing.T) {
	require := require.New(t)

	// Setup VM
	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	// Create a shielded transaction
	tx := &Transaction{
		Type:    TransactionTypeTransfer,
		Version: 1,
		Nullifiers: [][]byte{
			make([]byte, 32), // dummy nullifier
		},
		Outputs: []*ShieldedOutput{
			{
				Commitment:      make([]byte, 32),
				EncryptedNote:   make([]byte, 256),
				EphemeralPubKey: make([]byte, 32),
				OutputProof:     make([]byte, 128),
			},
		},
		Proof: &ZKProof{
			ProofType: "groth16",
			ProofData: make([]byte, 256),
			PublicInputs: [][]byte{
				make([]byte, 32), // nullifier
				make([]byte, 32), // output commitment
			},
		},
		Fee:    1000,
		Expiry: 0,
	}

	// Compute transaction ID
	tx.ID = tx.ComputeID()

	// Validate transaction
	require.NoError(tx.ValidateBasic())

	// Add to mempool
	require.NoError(vm.mempool.AddTransaction(tx))

	// Verify in mempool
	require.True(vm.mempool.HasTransaction(tx.ID))
	require.Equal(1, vm.mempool.Size())
}

func TestPrivateAddress(t *testing.T) {
	require := require.New(t)

	// Setup VM with privacy enabled
	vm := setupTestVMWithPrivacy(t)
	defer vm.Shutdown(context.Background())

	// Generate a private address
	addr, err := vm.addressManager.GenerateAddress()
	require.NoError(err)
	require.NotNil(addr)

	// Verify address components
	require.Len(addr.Address, 32)
	require.Len(addr.ViewingKey, 32)
	require.Len(addr.SpendingKey, 32)
	require.Len(addr.Diversifier, 11)
	require.Len(addr.IncomingViewKey, 32)

	// Test address retrieval
	retrieved, err := vm.addressManager.GetAddress(addr.Address)
	require.NoError(err)
	require.Equal(addr.Address, retrieved.Address)
}

// Helper functions

func setupTestVM(t *testing.T) *VM {
	ctx := context.Background()
	chainCtx := &consensusctx.Context{
		ChainID: ids.GenerateTestID(),
		Log:     log.NoLog{},
	}

	db := memdb.New()

	genesis := &Genesis{
		Timestamp:  1607144400,
		InitialTxs: []*Transaction{},
	}
	genesisBytes, _ := Codec.Marshal(codecVersion, genesis)

	config := ZConfig{
		ProofSystem:      "groth16",
		MaxUTXOsPerBlock: 100,
		ProofCacheSize:   1000,
	}
	configBytes, _ := Codec.Marshal(codecVersion, config)

	vm := &VM{}
	toEngine := make(chan core.Message, 1)

	require.NoError(t, vm.Initialize(ctx, chainCtx, db, genesisBytes, nil, configBytes, toEngine, nil, nil))

	return vm
}

func setupTestVMWithPrivacy(t *testing.T) *VM {
	ctx := context.Background()
	chainCtx := &consensusctx.Context{
		ChainID: ids.GenerateTestID(),
		Log:     log.NoLog{},
	}

	db := memdb.New()

	genesis := &Genesis{
		Timestamp:  1607144400,
		InitialTxs: []*Transaction{},
	}
	genesisBytes, _ := Codec.Marshal(codecVersion, genesis)

	config := ZConfig{
		EnablePrivateAddresses: true,
		ProofSystem:            "groth16",
		MaxUTXOsPerBlock:       100,
		ProofCacheSize:         1000,
	}
	configBytes, _ := Codec.Marshal(codecVersion, config)

	vm := &VM{}
	toEngine := make(chan core.Message, 1)

	require.NoError(t, vm.Initialize(ctx, chainCtx, db, genesisBytes, nil, configBytes, toEngine, nil, nil))

	return vm
}
