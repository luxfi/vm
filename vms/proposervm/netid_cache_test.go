// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package proposervm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/cache/lru"
	"github.com/luxfi/ids"
)

// mockValidatorState implements consensus.ValidatorState for testing
type mockValidatorState struct {
	getNetworkIDCallCount int
	netIDMap              map[ids.ID]ids.ID
}

func (m *mockValidatorState) GetNetworkID(chainID ids.ID) (ids.ID, error) {
	m.getNetworkIDCallCount++
	if netID, ok := m.netIDMap[chainID]; ok {
		return netID, nil
	}
	return ids.Empty, nil
}

func (m *mockValidatorState) GetChainID(ids.ID) (ids.ID, error) {
	return ids.Empty, nil
}

func (m *mockValidatorState) GetSubnetID(chainID ids.ID) (ids.ID, error) {
	return ids.Empty, nil
}

func (m *mockValidatorState) GetValidatorSet(uint64, ids.ID) (map[ids.NodeID]uint64, error) {
	return nil, nil
}

func (m *mockValidatorState) GetCurrentHeight(context.Context) (uint64, error) {
	return 0, nil
}

func (m *mockValidatorState) GetMinimumHeight(context.Context) (uint64, error) {
	return 0, nil
}

// TestValidatorStateWrapperCache verifies NetID caching in validatorStateWrapper
func TestValidatorStateWrapperCache(t *testing.T) {
	require := require.New(t)

	chainID1 := ids.GenerateTestID()
	netID1 := ids.GenerateTestID()

	chainID2 := ids.GenerateTestID()
	netID2 := ids.GenerateTestID()

	mock := &mockValidatorState{
		netIDMap: map[ids.ID]ids.ID{
			chainID1: netID1,
			chainID2: netID2,
		},
	}

	// Create wrapper with cache
	wrapper := &validatorStateWrapper{
		ctx:         context.Background(),
		vs:          mock,
		netIDsCache: lru.NewCache[ids.ID, ids.ID](4096),
	}

	ctx := context.Background()

	// First call - cache miss
	result1, err := wrapper.GetNetworkID(ctx, chainID1)
	require.NoError(err)
	require.Equal(netID1, result1)
	require.Equal(1, mock.getNetworkIDCallCount, "First call should hit underlying state")

	// Second call - cache hit
	result2, err := wrapper.GetNetworkID(ctx, chainID1)
	require.NoError(err)
	require.Equal(netID1, result2)
	require.Equal(1, mock.getNetworkIDCallCount, "Second call should use cache")

	// Different chainID - cache miss
	result3, err := wrapper.GetNetworkID(ctx, chainID2)
	require.NoError(err)
	require.Equal(netID2, result3)
	require.Equal(2, mock.getNetworkIDCallCount, "Different chainID should miss cache")

	// Same chainID again - cache hit
	result4, err := wrapper.GetNetworkID(ctx, chainID2)
	require.NoError(err)
	require.Equal(netID2, result4)
	require.Equal(2, mock.getNetworkIDCallCount, "Cached value should be used")
}

// TestInterfacesToConsensusValidatorStateAdapterCache verifies NetID caching in adapter
func TestInterfacesToConsensusValidatorStateAdapterCache(t *testing.T) {
	require := require.New(t)

	chainID1 := ids.GenerateTestID()
	netID1 := ids.GenerateTestID()

	mock := &mockValidatorState{
		netIDMap: map[ids.ID]ids.ID{
			chainID1: netID1,
		},
	}

	// Create adapter with cache
	adapter := &interfacesToConsensusValidatorStateAdapter{
		ctx:         context.Background(),
		vs:          mock,
		netIDsCache: lru.NewCache[ids.ID, ids.ID](4096),
	}

	// First call - cache miss
	result1, err := adapter.GetNetworkID(chainID1)
	require.NoError(err)
	require.Equal(netID1, result1)
	require.Equal(1, mock.getNetworkIDCallCount, "First call should hit underlying state")

	// Second call - cache hit
	result2, err := adapter.GetNetworkID(chainID1)
	require.NoError(err)
	require.Equal(netID1, result2)
	require.Equal(1, mock.getNetworkIDCallCount, "Second call should use cache")
}

// TestNetIDCacheSize verifies cache eviction works correctly
func TestNetIDCacheSize(t *testing.T) {
	require := require.New(t)

	mock := &mockValidatorState{
		netIDMap: make(map[ids.ID]ids.ID),
	}

	// Create wrapper with small cache size for testing eviction
	wrapper := &validatorStateWrapper{
		ctx:         context.Background(),
		vs:          mock,
		netIDsCache: lru.NewCache[ids.ID, ids.ID](2), // Only cache 2 entries
	}

	ctx := context.Background()

	// Generate test IDs
	chainIDs := make([]ids.ID, 3)
	netIDs := make([]ids.ID, 3)
	for i := range chainIDs {
		chainIDs[i] = ids.GenerateTestID()
		netIDs[i] = ids.GenerateTestID()
		mock.netIDMap[chainIDs[i]] = netIDs[i]
	}

	// Fill cache with 2 entries
	_, err := wrapper.GetNetworkID(ctx, chainIDs[0])
	require.NoError(err)
	require.Equal(1, mock.getNetworkIDCallCount)

	_, err = wrapper.GetNetworkID(ctx, chainIDs[1])
	require.NoError(err)
	require.Equal(2, mock.getNetworkIDCallCount)

	// Add third entry - should evict oldest
	_, err = wrapper.GetNetworkID(ctx, chainIDs[2])
	require.NoError(err)
	require.Equal(3, mock.getNetworkIDCallCount)

	// Access first entry again - should be cache miss (evicted)
	_, err = wrapper.GetNetworkID(ctx, chainIDs[0])
	require.NoError(err)
	require.Equal(4, mock.getNetworkIDCallCount, "First entry should have been evicted")

	// Access second entry - should also be cache miss (was evicted when we added chainIDs[0])
	// Cache state after adding third: [1, 2]
	// Cache state after re-adding first: [2, 0] (1 was evicted as oldest)
	_, err = wrapper.GetNetworkID(ctx, chainIDs[1])
	require.NoError(err)
	require.Equal(5, mock.getNetworkIDCallCount, "Second entry should have been evicted when first was re-added")
}
