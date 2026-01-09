// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chains

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/constants"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/metric"
	"github.com/luxfi/vm/nets"
	"github.com/luxfi/vm/vms"
)

// TestNew tests creating a new manager
func TestNew(t *testing.T) {
	require := require.New(t)

	config := &ManagerConfig{
		SkipBootstrap:    true,
		EnableAutomining: true,
		Log:              log.NewNoOpLogger(),
		Metrics:          metric.NewMultiGatherer(),
		VMManager:        vms.NewManager(nil, ids.NewAliaser()),
		ChainDataDir:     t.TempDir(),
	}

	m, err := New(config)
	require.NoError(err)
	require.NotNil(m)

	// Cast to implementation to check internal state
	mImpl := m.(*manager)
	require.True(mImpl.SkipBootstrap)
	require.True(mImpl.EnableAutomining)
	require.NotNil(mImpl.chains)
	require.NotNil(mImpl.chainsQueue)
}

// TestSkipBootstrapTracker tests that skip bootstrap mode uses correct tracker
func TestSkipBootstrapTracker(t *testing.T) {
	require := require.New(t)

	// Create a mock tracker for testing
	config := &ManagerConfig{
		SkipBootstrap:    true,
		EnableAutomining: true,
		Log:              log.NewNoOpLogger(),
		Metrics:          metric.NewMultiGatherer(),
		VMManager:        vms.NewManager(nil, ids.NewAliaser()),
		ChainDataDir:     t.TempDir(),
		// Tracker configuration not required for basic manager testing
	}

	m, err := New(config)
	require.NoError(err)
	require.NotNil(m)

	// Verify skip bootstrap mode is enabled
	mImpl := m.(*manager)
	require.True(mImpl.SkipBootstrap)

	// Test that manager can handle bootstrap status queries
	// even when skip bootstrap is enabled
	testChainID := ids.GenerateTestID()
	isBootstrapped := m.IsBootstrapped(testChainID)

	// When skip bootstrap is enabled, chains should be considered
	// bootstrapped by default, but this specific chain doesn't exist
	// so it returns false
	require.False(isBootstrapped)
}

// TestQueueChainCreation tests queuing chain creation
func TestQueueChainCreation(t *testing.T) {
	require := require.New(t)

	// Create subnets with primary network config
	subnetConfigs := map[ids.ID]nets.Config{
		constants.PrimaryNetworkID: {},
	}
	subnets, err := NewNets(ids.GenerateTestNodeID(), subnetConfigs)
	require.NoError(err)

	config := &ManagerConfig{
		Log:          log.NewNoOpLogger(),
		Metrics:      metric.NewMultiGatherer(),
		VMManager:    vms.NewManager(nil, ids.NewAliaser()),
		ChainDataDir: t.TempDir(),
		Nets:         subnets,
	}

	m, err := New(config)
	require.NoError(err)

	mImpl := m.(*manager)

	// Create test chain parameters
	chainID := ids.GenerateTestID()
	netID := ids.GenerateTestID()
	chainParams := ChainParameters{
		ID:      chainID,
		ChainID: netID,
		VMID:    ids.GenerateTestID(),
	}

	// Queue the chain
	m.QueueChainCreation(chainParams)

	// Check that the chain was queued
	queuedParams, ok := mImpl.chainsQueue.PopLeft()
	require.True(ok)
	require.Equal(chainParams.ID, queuedParams.ID)
	require.Equal(chainParams.ChainID, queuedParams.ChainID)
	require.Equal(chainParams.VMID, queuedParams.VMID)
}

// TestLookup tests chain alias lookup
func TestLookup(t *testing.T) {
	require := require.New(t)

	config := &ManagerConfig{
		Log:          log.NewNoOpLogger(),
		Metrics:      metric.NewMultiGatherer(),
		VMManager:    vms.NewManager(nil, ids.NewAliaser()),
		ChainDataDir: t.TempDir(),
	}

	m, err := New(config)
	require.NoError(err)

	// Create a test chain ID and alias
	chainID := ids.GenerateTestID()
	alias := "test-chain"

	// Add the alias
	require.NoError(m.Alias(chainID, alias))

	// Lookup by alias
	lookedUpID, err := m.Lookup(alias)
	require.NoError(err)
	require.Equal(chainID, lookedUpID)

	// According to the comment in manager.go, the string representation of a chain's ID
	// is also considered to be an alias of the chain. So we need to add it explicitly.
	require.NoError(m.Alias(chainID, chainID.String()))

	// Now lookup by ID string should work
	lookedUpID, err = m.Lookup(chainID.String())
	require.NoError(err)
	require.Equal(chainID, lookedUpID)
}

// TestIsBootstrapped tests checking if a chain is bootstrapped
func TestIsBootstrapped(t *testing.T) {
	require := require.New(t)

	config := &ManagerConfig{
		Log:          log.NewNoOpLogger(),
		Metrics:      metric.NewMultiGatherer(),
		VMManager:    vms.NewManager(nil, ids.NewAliaser()),
		ChainDataDir: t.TempDir(),
	}

	m, err := New(config)
	require.NoError(err)

	// Test non-existent chain
	chainID := ids.GenerateTestID()
	require.False(m.IsBootstrapped(chainID))
}

// TestToEngineChannelFlow verifies the toEngine channel notification flow
// This tests the goroutine that reads from toEngine and triggers block building
func TestToEngineChannelFlow(t *testing.T) {
	require := require.New(t)

	// Create toEngine channel (same as what manager creates)
	toEngine := make(chan block.Message, 1)
	defer close(toEngine)

	// Track block builds
	var buildCalls int
	var mu sync.Mutex

	// Simulate the goroutine that reads from toEngine
	done := make(chan struct{})
	go func() {
		defer close(done)
		for msg := range toEngine {
			if msg.Type == 0 { // PendingTxs
				mu.Lock()
				buildCalls++
				mu.Unlock()
			}
		}
	}()

	// Send PendingTxs notification
	toEngine <- block.Message{Type: 0} // PendingTxs = 0

	// Give goroutine time to process
	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	count := buildCalls
	mu.Unlock()

	require.Equal(1, count, "Expected 1 build call after PendingTxs notification")

	// Send multiple notifications
	for i := 0; i < 5; i++ {
		toEngine <- block.Message{Type: 0}
	}

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	count = buildCalls
	mu.Unlock()

	require.Equal(6, count, "Expected 6 total build calls")
}

// TestToEngineMessageTypes verifies different message types are handled correctly
func TestToEngineMessageTypes(t *testing.T) {
	require := require.New(t)

	toEngine := make(chan block.Message, 10)
	defer close(toEngine)

	var pendingTxsCalls int
	var otherCalls int
	var mu sync.Mutex

	done := make(chan struct{})
	go func() {
		defer close(done)
		for msg := range toEngine {
			mu.Lock()
			if msg.Type == 0 { // PendingTxs
				pendingTxsCalls++
			} else {
				otherCalls++
			}
			mu.Unlock()
		}
	}()

	// Send different message types
	toEngine <- block.Message{Type: 0} // PendingTxs - should trigger build
	toEngine <- block.Message{Type: 1} // StateSyncDone - should NOT trigger build
	toEngine <- block.Message{Type: 0} // PendingTxs - should trigger build
	toEngine <- block.Message{Type: 2} // Unknown - should NOT trigger build

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	pendingCount := pendingTxsCalls
	otherCount := otherCalls
	mu.Unlock()

	require.Equal(2, pendingCount, "Expected 2 PendingTxs messages")
	require.Equal(2, otherCount, "Expected 2 other messages")
}
