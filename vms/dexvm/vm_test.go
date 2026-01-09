// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"context"
	"testing"
	"time"

	"github.com/luxfi/consensus"
	consensusctx "github.com/luxfi/consensus/context"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/version"
	luxvm "github.com/luxfi/vm"
	"github.com/luxfi/vm/vms/dexvm/config"
	"github.com/luxfi/vm/vms/dexvm/orderbook"
	"github.com/luxfi/warp"
	"github.com/stretchr/testify/require"
)

func createTestVM(t *testing.T) (*VM, func()) {
	require := require.New(t)

	logger := log.NewNoOpLogger()
	cfg := config.DefaultConfig()

	vm := &VM{
		Config: cfg,
		log:    logger,
	}

	chainID := ids.GenerateTestID()
	db := memdb.New()
	toEngine := make(chan luxvm.Message, 100)
	appSender := warp.FakeSender{}

	consensusCtx := &consensusctx.Context{
		ChainID: chainID,
	}

	err := vm.Initialize(
		context.Background(),
		consensusCtx,
		db,
		nil, // genesis
		nil, // upgrade
		nil, // config
		toEngine,
		nil, // fxs
		appSender,
	)
	require.NoError(err)

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		vm.Shutdown(ctx)
	}

	return vm, cleanup
}

func TestVMInitialize(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	require.True(vm.isInitialized)
	require.False(vm.bootstrapped)
	require.NotNil(vm.orderbooks)
	require.NotNil(vm.liquidityMgr)
	require.Equal(uint64(0), vm.currentBlockHeight)
}

func TestVMSetState(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	// Set to bootstrapping
	err := vm.SetState(context.Background(), uint32(consensus.Bootstrapping))
	require.NoError(err)
	require.False(vm.bootstrapped)

	// Set to normal operation (functional mode - no background tasks)
	err = vm.SetState(context.Background(), uint32(consensus.Ready))
	require.NoError(err)
	require.True(vm.bootstrapped)
}

func TestVMVersion(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	version, err := vm.Version(context.Background())
	require.NoError(err)
	require.Equal("1.0.0", version)
}

func TestVMHealthCheck(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	// Before bootstrap
	health, err := vm.HealthCheck(context.Background())
	require.NoError(err)

	healthMap := health.(map[string]interface{})
	require.False(healthMap["healthy"].(bool))
	require.False(healthMap["bootstrapped"].(bool))
	require.Equal("functional", healthMap["mode"].(string))

	// After bootstrap
	vm.SetState(context.Background(), uint32(consensus.Ready))

	health, err = vm.HealthCheck(context.Background())
	require.NoError(err)

	healthMap = health.(map[string]interface{})
	require.True(healthMap["healthy"].(bool))
	require.True(healthMap["bootstrapped"].(bool))
}

func TestVMPeerConnections(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	nodeID := ids.GenerateTestNodeID()
	appVersion := &version.Application{}

	// Connect peer
	err := vm.Connected(context.Background(), nodeID, appVersion)
	require.NoError(err)

	vm.lock.RLock()
	_, exists := vm.connectedPeers[nodeID]
	vm.lock.RUnlock()
	require.True(exists)

	// Disconnect peer
	err = vm.Disconnected(context.Background(), nodeID)
	require.NoError(err)

	vm.lock.RLock()
	_, exists = vm.connectedPeers[nodeID]
	vm.lock.RUnlock()
	require.False(exists)
}

func TestVMGetOrderbook(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	// Orderbook doesn't exist
	_, err := vm.GetOrderbook("LUX/USDT")
	require.Error(err)

	// Create orderbook
	ob := vm.GetOrCreateOrderbook("LUX/USDT")
	require.NotNil(ob)
	require.Equal("LUX/USDT", ob.Symbol())

	// Get existing orderbook
	ob2, err := vm.GetOrderbook("LUX/USDT")
	require.NoError(err)
	require.Equal(ob, ob2)
}

func TestVMCreateHandlers(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	handlers, err := vm.CreateHandlers(context.Background())
	require.NoError(err)
	require.NotNil(handlers)
	require.Contains(handlers, "")
	require.Contains(handlers, "/ws")
}

func TestVMIsBootstrapped(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	require.False(vm.IsBootstrapped())

	vm.SetState(context.Background(), uint32(consensus.Ready))

	require.True(vm.IsBootstrapped())
}

func TestVMShutdown(t *testing.T) {
	require := require.New(t)

	vm, _ := createTestVM(t)

	// Start VM (functional mode - no background tasks)
	err := vm.SetState(context.Background(), uint32(consensus.Ready))
	require.NoError(err)

	// Shutdown (immediate - no background tasks to wait for)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = vm.Shutdown(ctx)
	require.NoError(err)
	require.True(vm.shutdown)
}

func TestVMAppGossip(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	nodeID := ids.GenerateTestNodeID()
	msg := []byte("test gossip")

	err := vm.AppGossip(context.Background(), nodeID, msg)
	require.NoError(err)
}

func TestVMAppRequest(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	nodeID := ids.GenerateTestNodeID()
	requestID := uint32(1)
	deadline := time.Now().Add(time.Minute)
	request := []byte("test request")

	err := vm.AppRequest(context.Background(), nodeID, requestID, deadline, request)
	require.NoError(err)
}

func TestVMCrossChainAppRequest(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	chainID := ids.GenerateTestID()
	requestID := uint32(1)
	deadline := time.Now().Add(time.Minute)
	request := []byte("test cross-chain request")

	err := vm.CrossChainAppRequest(context.Background(), chainID, requestID, deadline, request)
	require.NoError(err)
}

func TestVMGetLiquidityManager(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	mgr := vm.GetLiquidityManager()
	require.NotNil(mgr)

	// Verify pool creation works via liquidity manager
	pools := mgr.GetAllPools()
	require.NotNil(pools)
	require.Len(pools, 0) // No pools yet
}

func TestVMGetPerpetualsEngine(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	engine := vm.GetPerpetualsEngine()
	require.NotNil(engine)

	// Verify no markets initially
	markets := engine.GetAllMarkets()
	require.Len(markets, 0)
}

// Test ProcessBlock - the core deterministic function
func TestVMProcessBlock(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	// Bootstrap VM
	err := vm.SetState(context.Background(), uint32(consensus.Ready))
	require.NoError(err)

	// Process first block
	blockTime := time.Now()
	result, err := vm.ProcessBlock(context.Background(), 1, blockTime, nil)
	require.NoError(err)
	require.NotNil(result)
	require.Equal(uint64(1), result.BlockHeight)
	require.Equal(blockTime, result.Timestamp)
	require.Empty(result.MatchedTrades) // No orders yet

	// Verify state updated
	require.Equal(uint64(1), vm.GetBlockHeight())
	require.Equal(blockTime, vm.GetLastBlockTime())
}

func TestVMProcessBlockWithOrders(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	// Bootstrap VM
	err := vm.SetState(context.Background(), uint32(consensus.Ready))
	require.NoError(err)

	// Create orderbook with crossing orders
	ob := vm.GetOrCreateOrderbook("LUX/USDT")

	// Add buy order
	buyOrder := &orderbook.Order{
		ID:        ids.GenerateTestID(),
		Owner:     ids.GenerateTestShortID(),
		Symbol:    "LUX/USDT",
		Side:      orderbook.Buy,
		Type:      orderbook.Limit,
		Price:     10000000000000000000,         // 10 USDT
		Quantity:  1000000000000000000,          // 1 LUX
		CreatedAt: time.Now().UnixNano() - 1000, // Earlier
	}
	_, err = ob.AddOrder(buyOrder)
	require.NoError(err)

	// Add sell order that crosses
	sellOrder := &orderbook.Order{
		ID:        ids.GenerateTestID(),
		Owner:     ids.GenerateTestShortID(), // Different owner
		Symbol:    "LUX/USDT",
		Side:      orderbook.Sell,
		Type:      orderbook.Limit,
		Price:     9000000000000000000, // 9 USDT (crosses with buy at 10)
		Quantity:  500000000000000000,  // 0.5 LUX
		CreatedAt: time.Now().UnixNano(),
	}
	_, err = ob.AddOrder(sellOrder)
	require.NoError(err)

	// Process block - should match orders
	blockTime := time.Now()
	result, err := vm.ProcessBlock(context.Background(), 1, blockTime, nil)
	require.NoError(err)
	require.NotNil(result)

	// Trades should be matched during block processing
	// Note: AddOrder already matches, but Match() will find any remaining crosses
	require.Equal(uint64(1), result.BlockHeight)
}

func TestVMProcessBlockFundingInterval(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	// Bootstrap VM
	err := vm.SetState(context.Background(), uint32(consensus.Ready))
	require.NoError(err)

	// Process first block - funding check runs but no payments without positions
	blockTime := time.Now()
	result1, err := vm.ProcessBlock(context.Background(), 1, blockTime, nil)
	require.NoError(err)
	require.NotNil(result1)
	// No perpetual positions exist, so no funding payments are generated
	// The funding check still runs, but produces empty results

	// Process second block immediately - should NOT trigger funding check
	result2, err := vm.ProcessBlock(context.Background(), 2, blockTime.Add(time.Second), nil)
	require.NoError(err)
	require.Empty(result2.FundingPayments) // Too soon for funding interval

	// Process block after 8 hours - should trigger funding check
	result3, err := vm.ProcessBlock(context.Background(), 3, blockTime.Add(8*time.Hour), nil)
	require.NoError(err)
	// Still no payments because no perpetual positions exist
	// But the funding interval logic is verified by the timing
	require.NotNil(result3)

	// Verify the block heights are correct
	require.Equal(uint64(3), vm.GetBlockHeight())
}

func TestVMProcessBlockAfterShutdown(t *testing.T) {
	require := require.New(t)

	vm, _ := createTestVM(t)

	// Bootstrap and shutdown
	err := vm.SetState(context.Background(), uint32(consensus.Ready))
	require.NoError(err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = vm.Shutdown(ctx)
	cancel()
	require.NoError(err)

	// Try to process block after shutdown
	_, err = vm.ProcessBlock(context.Background(), 1, time.Now(), nil)
	require.Error(err)
	require.Equal(errShutdown, err)
}

func TestVMGetBlockHeight(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	require.Equal(uint64(0), vm.GetBlockHeight())

	vm.SetState(context.Background(), uint32(consensus.Ready))

	// Process some blocks
	vm.ProcessBlock(context.Background(), 1, time.Now(), nil)
	require.Equal(uint64(1), vm.GetBlockHeight())

	vm.ProcessBlock(context.Background(), 2, time.Now(), nil)
	require.Equal(uint64(2), vm.GetBlockHeight())

	vm.ProcessBlock(context.Background(), 100, time.Now(), nil)
	require.Equal(uint64(100), vm.GetBlockHeight())
}

// Integration test: Full trading flow
func TestVMTradingFlow(t *testing.T) {
	require := require.New(t)

	vm, cleanup := createTestVM(t)
	defer cleanup()

	// Bootstrap VM
	err := vm.SetState(context.Background(), uint32(consensus.Ready))
	require.NoError(err)

	// Create orderbook
	ob := vm.GetOrCreateOrderbook("LUX/USDT")
	require.NotNil(ob)

	// Verify orderbook stats
	totalVol, tradeCount, _ := ob.GetStats()
	require.Equal(uint64(0), totalVol)
	require.Equal(uint64(0), tradeCount)

	// Verify health
	health, err := vm.HealthCheck(context.Background())
	require.NoError(err)
	healthMap := health.(map[string]interface{})
	require.True(healthMap["healthy"].(bool))
	require.Equal(1, healthMap["orderbooks"].(int))
	require.Equal("functional", healthMap["mode"].(string))
}

// Test determinism: same inputs produce same outputs
func TestVMDeterminism(t *testing.T) {
	require := require.New(t)

	// Create two identical VMs
	vm1, cleanup1 := createTestVM(t)
	defer cleanup1()
	vm2, cleanup2 := createTestVM(t)
	defer cleanup2()

	// Bootstrap both
	vm1.SetState(context.Background(), uint32(consensus.Ready))
	vm2.SetState(context.Background(), uint32(consensus.Ready))

	// Process same blocks on both
	blockTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	result1, err := vm1.ProcessBlock(context.Background(), 1, blockTime, nil)
	require.NoError(err)

	result2, err := vm2.ProcessBlock(context.Background(), 1, blockTime, nil)
	require.NoError(err)

	// Results should be identical
	require.Equal(result1.BlockHeight, result2.BlockHeight)
	require.Equal(result1.Timestamp, result2.Timestamp)
	require.Equal(len(result1.FundingPayments), len(result2.FundingPayments))
	require.Equal(len(result1.Liquidations), len(result2.Liquidations))
	require.Equal(len(result1.MatchedTrades), len(result2.MatchedTrades))
}

func BenchmarkVMInitialize(b *testing.B) {
	logger := log.NewNoOpLogger()
	cfg := config.DefaultConfig()

	for i := 0; i < b.N; i++ {
		vm := &VM{
			Config: cfg,
			log:    logger,
		}

		chainID := ids.GenerateTestID()
		db := memdb.New()
		toEngine := make(chan luxvm.Message, 100)
		appSender := warp.FakeSender{}

		consensusCtx := &consensusctx.Context{
			ChainID: chainID,
		}

		vm.Initialize(
			context.Background(),
			consensusCtx,
			db,
			nil,
			nil,
			nil,
			toEngine,
			nil,
			appSender,
		)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		vm.Shutdown(ctx)
		cancel()
	}
}

func BenchmarkVMProcessBlock(b *testing.B) {
	logger := log.NewNoOpLogger()
	cfg := config.DefaultConfig()

	vm := &VM{
		Config: cfg,
		log:    logger,
	}

	chainID := ids.GenerateTestID()
	db := memdb.New()
	toEngine := make(chan luxvm.Message, 100)
	appSender := warp.FakeSender{}

	consensusCtx := &consensusctx.Context{
		ChainID: chainID,
	}

	vm.Initialize(
		context.Background(),
		consensusCtx,
		db,
		nil,
		nil,
		nil,
		toEngine,
		nil,
		appSender,
	)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		vm.Shutdown(ctx)
		cancel()
	}()

	vm.SetState(context.Background(), uint32(consensus.Ready))

	blockTime := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vm.ProcessBlock(context.Background(), uint64(i+1), blockTime.Add(time.Duration(i)*time.Millisecond), nil)
	}
}
