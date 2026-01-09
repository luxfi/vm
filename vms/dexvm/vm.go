// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/rpc/v2"
	"github.com/luxfi/log"
	"github.com/luxfi/metric"

	consensusctx "github.com/luxfi/consensus/context"
	consensuscore "github.com/luxfi/consensus/core"
	"github.com/luxfi/database"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/version"
	"github.com/luxfi/vm/utils/timer/mockable"
	"github.com/luxfi/vm/vms/dexvm/api"
	"github.com/luxfi/vm/vms/dexvm/config"
	"github.com/luxfi/vm/vms/dexvm/liquidity"
	"github.com/luxfi/vm/vms/dexvm/mev"
	"github.com/luxfi/vm/vms/dexvm/orderbook"
	"github.com/luxfi/vm/vms/dexvm/perpetuals"
	"github.com/luxfi/warp"
)

var (
	errUnknownState    = errors.New("unknown state")
	errNotBootstrapped = errors.New("VM not bootstrapped")
	errShutdown        = errors.New("VM is shutting down")

	_ = errNotBootstrapped
	_ = errShutdown
)

// BlockResult represents the deterministic result of processing a block.
// All state changes are captured here for verifiability.
type BlockResult struct {
	// BlockHeight is the height of the processed block
	BlockHeight uint64

	// Timestamp is when this block was processed
	Timestamp time.Time

	// MatchedTrades from order matching in this block
	MatchedTrades []orderbook.Trade

	// FundingPayments processed in this block (if any)
	FundingPayments []*perpetuals.FundingPayment

	// Liquidations executed in this block (if any)
	Liquidations []*perpetuals.LiquidationEvent

	// StateRoot is the merkle root of state after this block
	StateRoot ids.ID
}

// VM implements the DEX Virtual Machine using a pure functional architecture.
// All state transitions happen deterministically within block processing:
//   - Central Limit Order Book (CLOB) trading
//   - Automated Market Maker (AMM) liquidity pools
//   - Cross-chain atomic swaps via Warp messaging
//   - 1ms block times for ultra-low latency HFT support
//
// DESIGN: No background goroutines. All operations are block-driven and deterministic.
// This ensures:
//   - Every node produces identical state from identical inputs
//   - No race conditions or non-deterministic behavior
//   - Easy to test and verify
//   - Replay-safe for auditing
type VM struct {
	config.Config

	// Logger for this VM
	log log.Logger

	// Lock for thread safety (only for API access, not consensus)
	lock sync.RWMutex

	// Consensus context - provides chain identity and network info
	consensusCtx *consensusctx.Context

	// Chain identity
	chainID ids.ID

	// Database management
	baseDB database.Database
	db     *versiondb.Database

	// Used to check local time
	clock mockable.Clock

	// Metrics
	registerer metric.Registerer

	// Network peers
	connectedPeers map[ids.NodeID]*version.Application

	// Application sender for gossip
	appSender warp.Sender

	// DEX components (all operations on these are deterministic)
	orderbooks      map[string]*orderbook.Orderbook    // symbol -> orderbook
	liquidityMgr    *liquidity.Manager                 // AMM liquidity pools
	perpetualsEng   *perpetuals.Engine                 // Perpetual futures engine
	commitmentStore *mev.CommitmentStore               // MEV protection commit-reveal
	adlEngine       *perpetuals.AutoDeleveragingEngine // Auto-deleveraging

	// Block state
	currentBlockHeight uint64
	lastBlockTime      time.Time
	lastFundingTime    time.Time // Tracks when funding was last processed

	// Lifecycle state
	bootstrapped  bool
	isInitialized bool
	shutdown      bool

	// Channel for sending messages to consensus engine
	toEngine chan consensuscore.Message
}

// NewVMForTest creates a new VM instance for testing purposes.
// This allows external test packages to create VM instances without
// needing to access internal fields directly.
func NewVMForTest(cfg config.Config, logger log.Logger) *VM {
	return &VM{
		Config: cfg,
		log:    logger,
	}
}

// Initialize implements consensuscore.VM interface.
// It sets up the VM with the provided context, database, and genesis data.
func (vm *VM) Initialize(
	ctx context.Context,
	consensusCtx interface{},
	dbManager interface{},
	genesisBytes []byte,
	upgradeBytes []byte,
	configBytes []byte,
	msgChan interface{},
	fxs []interface{},
	appSender interface{},
) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	// Cast consensus context
	vm.consensusCtx = consensusCtx.(*consensusctx.Context)
	vm.chainID = vm.consensusCtx.ChainID

	// Setup database
	vm.baseDB = dbManager.(database.Database)
	vm.db = versiondb.New(vm.baseDB)

	// Setup message channel
	vm.toEngine = msgChan.(chan consensuscore.Message)

	// Setup app sender
	if appSender != nil {
		vm.appSender = appSender.(warp.Sender)
	}

	// Initialize peer tracking
	vm.connectedPeers = make(map[ids.NodeID]*version.Application)

	// Initialize DEX components
	vm.orderbooks = make(map[string]*orderbook.Orderbook)
	vm.liquidityMgr = liquidity.NewManager()
	vm.perpetualsEng = perpetuals.NewEngine()
	vm.commitmentStore = mev.NewCommitmentStore()
	vm.adlEngine = perpetuals.NewAutoDeleveragingEngine(perpetuals.DefaultADLConfig())

	// Initialize block state
	vm.currentBlockHeight = 0
	vm.lastBlockTime = time.Time{}
	vm.lastFundingTime = time.Time{}

	// Parse genesis if provided
	if len(genesisBytes) > 0 {
		if err := vm.parseGenesis(genesisBytes); err != nil {
			return fmt.Errorf("failed to parse genesis: %w", err)
		}
	}

	// Parse config if provided
	if len(configBytes) > 0 {
		if err := vm.parseConfig(configBytes); err != nil {
			return fmt.Errorf("failed to parse config: %w", err)
		}
	}

	vm.isInitialized = true
	if vm.log != nil {
		vm.log.Info("DEX VM initialized (functional mode)",
			"chainID", vm.chainID,
			"blockInterval", vm.Config.BlockInterval,
		)
	}

	return nil
}

// parseGenesis parses the genesis data and initializes initial state.
func (vm *VM) parseGenesis(genesisBytes []byte) error {
	// TODO: Implement genesis parsing
	// This would initialize:
	// - Initial trading pairs
	// - Initial liquidity pools
	// - Fee configurations
	// - Trusted chains for cross-chain
	return nil
}

// parseConfig parses and applies runtime configuration.
func (vm *VM) parseConfig(configBytes []byte) error {
	// TODO: Implement config parsing
	return nil
}

// SetState implements consensuscore.VM interface.
// It transitions the VM between bootstrapping and normal operation states.
// NOTE: No background goroutines are started - all operations are block-driven.
func (vm *VM) SetState(ctx context.Context, stateNum uint32) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	state := consensuscore.State(stateNum)
	switch state {
	case consensuscore.Bootstrapping:
		if vm.log != nil {
			vm.log.Info("DEX VM entering bootstrap state")
		}
		vm.bootstrapped = false
		return nil

	case consensuscore.Ready:
		if vm.log != nil {
			vm.log.Info("DEX VM entering ready state")
		}
		vm.bootstrapped = true
		return nil

	default:
		return fmt.Errorf("%w: %d", errUnknownState, stateNum)
	}
}

// ProcessBlock is the core function that processes all DEX operations deterministically.
// This is called by the consensus engine for each new block.
// All state changes happen here in a deterministic, reproducible manner.
//
// Operations performed per block:
//  1. Order matching for all orderbooks
//  2. Funding rate processing (every 8 hours)
//  3. Liquidation checks
//  4. State commitment
func (vm *VM) ProcessBlock(ctx context.Context, blockHeight uint64, blockTime time.Time, txs [][]byte) (*BlockResult, error) {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if vm.shutdown {
		return nil, errShutdown
	}

	result := &BlockResult{
		BlockHeight:     blockHeight,
		Timestamp:       blockTime,
		MatchedTrades:   make([]orderbook.Trade, 0),
		FundingPayments: make([]*perpetuals.FundingPayment, 0),
		Liquidations:    make([]*perpetuals.LiquidationEvent, 0),
	}

	// 1. Process all transactions in the block
	for _, tx := range txs {
		if err := vm.processTx(tx, result); err != nil {
			// Log but continue - individual tx failures don't fail the block
			if vm.log != nil {
				vm.log.Warn("Transaction failed", "error", err)
			}
		}
	}

	// 2. Run order matching for all active orderbooks
	result.MatchedTrades = vm.matchAllOrders()

	// 3. Check if funding should be processed (every 8 hours)
	if vm.shouldProcessFunding(blockTime) {
		result.FundingPayments = vm.processFunding(blockTime)
		vm.lastFundingTime = blockTime
	}

	// 4. Check and execute liquidations
	result.Liquidations = vm.processLiquidations()

	// 5. Update block state
	vm.currentBlockHeight = blockHeight
	vm.lastBlockTime = blockTime

	// 6. Compute state root (merkle root of all state)
	result.StateRoot = vm.computeStateRoot()

	if vm.log != nil {
		vm.log.Debug("Block processed",
			"height", blockHeight,
			"trades", len(result.MatchedTrades),
			"funding", len(result.FundingPayments),
			"liquidations", len(result.Liquidations),
		)
	}

	return result, nil
}

// processTx processes a single transaction.
func (vm *VM) processTx(tx []byte, result *BlockResult) error {
	// TODO: Decode and execute transaction
	// Transaction types:
	// - PlaceOrder
	// - CancelOrder
	// - AddLiquidity
	// - RemoveLiquidity
	// - Swap
	// - OpenPosition
	// - ClosePosition
	// - Deposit
	// - Withdraw
	return nil
}

// matchAllOrders runs the matching engine for all orderbooks.
// This is deterministic - same orders always produce same matches.
func (vm *VM) matchAllOrders() []orderbook.Trade {
	var allTrades []orderbook.Trade

	for symbol, ob := range vm.orderbooks {
		trades := ob.Match()
		if len(trades) > 0 {
			allTrades = append(allTrades, trades...)
			if vm.log != nil {
				vm.log.Debug("Matched trades", "symbol", symbol, "count", len(trades))
			}
		}
	}

	return allTrades
}

// shouldProcessFunding determines if funding should be processed.
// Funding happens every 8 hours (28800 seconds).
func (vm *VM) shouldProcessFunding(blockTime time.Time) bool {
	if vm.lastFundingTime.IsZero() {
		return true // First funding
	}

	fundingInterval := 8 * time.Hour
	return blockTime.Sub(vm.lastFundingTime) >= fundingInterval
}

// processFunding processes funding payments for all perpetual markets.
// This is deterministic based on current positions and mark prices.
func (vm *VM) processFunding(blockTime time.Time) []*perpetuals.FundingPayment {
	var allPayments []*perpetuals.FundingPayment

	for _, m := range vm.perpetualsEng.GetAllMarkets() {
		market, ok := m.(*perpetuals.Market)
		if !ok {
			continue
		}
		payments, err := vm.perpetualsEng.ProcessFunding(market.Symbol)
		if err != nil {
			if vm.log != nil {
				vm.log.Warn("Failed to process funding", "market", market.Symbol, "error", err)
			}
			continue
		}
		allPayments = append(allPayments, payments...)
	}

	return allPayments
}

// processLiquidations checks and executes liquidations for all markets.
// This is deterministic based on current prices and position health.
func (vm *VM) processLiquidations() []*perpetuals.LiquidationEvent {
	var allLiquidations []*perpetuals.LiquidationEvent

	for _, m := range vm.perpetualsEng.GetAllMarkets() {
		market, ok := m.(*perpetuals.Market)
		if !ok {
			continue
		}
		liquidations, err := vm.perpetualsEng.CheckAndLiquidate(market.Symbol)
		if err != nil {
			if vm.log != nil {
				vm.log.Warn("Failed to check liquidations", "market", market.Symbol, "error", err)
			}
			continue
		}
		allLiquidations = append(allLiquidations, liquidations...)
	}

	return allLiquidations
}

// computeStateRoot computes the merkle root of all state.
// This ensures all nodes agree on state after processing a block.
func (vm *VM) computeStateRoot() ids.ID {
	// TODO: Implement proper merkle tree computation over:
	// - All orderbook state
	// - All liquidity pool state
	// - All perpetual positions
	// - All account balances
	return ids.Empty
}

// Shutdown implements consensuscore.VM interface.
// It gracefully shuts down the VM.
// NOTE: No background tasks to wait for in functional mode.
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if vm.log != nil {
		vm.log.Info("Shutting down DEX VM")
	}

	vm.shutdown = true

	// Close database
	if vm.db != nil {
		if err := vm.db.Close(); err != nil {
			return fmt.Errorf("failed to close database: %w", err)
		}
	}

	if vm.log != nil {
		vm.log.Info("DEX VM shutdown complete")
	}

	return nil
}

// Version implements consensuscore.VM interface.
func (vm *VM) Version(ctx context.Context) (string, error) {
	return "1.0.0", nil
}

// CreateHandlers implements consensuscore.VM interface.
// It creates HTTP handlers for the DEX API.
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	server := rpc.NewServer()
	server.RegisterCodec(NewCodec(), "application/json")
	server.RegisterCodec(NewCodec(), "application/json;charset=UTF-8")

	// Register DEX API service
	service := api.NewService(vm)
	if err := server.RegisterService(service, "dex"); err != nil {
		return nil, fmt.Errorf("failed to register DEX service: %w", err)
	}

	return map[string]http.Handler{
		"":    server,
		"/ws": vm.createWebSocketHandler(),
	}, nil
}

// createWebSocketHandler creates a WebSocket handler for real-time updates.
func (vm *VM) createWebSocketHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement WebSocket handler for:
		// - Real-time orderbook updates
		// - Trade notifications
		// - Price feeds
		http.Error(w, "WebSocket not yet implemented", http.StatusNotImplemented)
	})
}

// HealthCheck implements consensuscore.VM interface.
func (vm *VM) HealthCheck(ctx context.Context) (interface{}, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()

	return map[string]interface{}{
		"healthy":      vm.isInitialized && vm.bootstrapped,
		"bootstrapped": vm.bootstrapped,
		"orderbooks":   len(vm.orderbooks),
		"pools":        len(vm.liquidityMgr.GetAllPools()),
		"perpMarkets":  len(vm.perpetualsEng.GetAllMarkets()),
		"blockHeight":  vm.currentBlockHeight,
		"mode":         "functional", // Indicates no background tasks
	}, nil
}

// Connected implements consensuscore.VM interface.
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, v *version.Application) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	vm.connectedPeers[nodeID] = v
	if vm.log != nil {
		vm.log.Debug("Peer connected", "nodeID", nodeID, "version", v)
	}
	return nil
}

// Disconnected implements consensuscore.VM interface.
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	delete(vm.connectedPeers, nodeID)
	if vm.log != nil {
		vm.log.Debug("Peer disconnected", "nodeID", nodeID)
	}
	return nil
}

// GetOrderbook returns the orderbook for a symbol.
func (vm *VM) GetOrderbook(symbol string) (*orderbook.Orderbook, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()

	ob, exists := vm.orderbooks[symbol]
	if !exists {
		return nil, fmt.Errorf("orderbook not found for symbol: %s", symbol)
	}
	return ob, nil
}

// GetOrCreateOrderbook returns or creates an orderbook for a symbol.
func (vm *VM) GetOrCreateOrderbook(symbol string) *orderbook.Orderbook {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	ob, exists := vm.orderbooks[symbol]
	if !exists {
		ob = orderbook.New(symbol)
		vm.orderbooks[symbol] = ob
	}
	return ob
}

// GetLiquidityManager returns the liquidity pool manager.
func (vm *VM) GetLiquidityManager() *liquidity.Manager {
	return vm.liquidityMgr
}

// GetPerpetualsEngine returns the perpetual futures engine.
func (vm *VM) GetPerpetualsEngine() api.PerpetualsEngine {
	return vm.perpetualsEng
}

// GetCommitmentStore returns the MEV protection commitment store.
func (vm *VM) GetCommitmentStore() api.CommitmentStore {
	return vm.commitmentStore
}

// GetADLEngine returns the auto-deleveraging engine.
func (vm *VM) GetADLEngine() api.ADLEngine {
	return vm.adlEngine
}

// IsBootstrapped returns true if the VM is fully bootstrapped.
func (vm *VM) IsBootstrapped() bool {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return vm.bootstrapped
}

// GetBlockHeight returns the current block height.
func (vm *VM) GetBlockHeight() uint64 {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return vm.currentBlockHeight
}

// GetLastBlockTime returns the timestamp of the last processed block.
func (vm *VM) GetLastBlockTime() time.Time {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return vm.lastBlockTime
}

// AppGossip implements consensuscore.VM interface.
// It handles gossiped messages from peers.
func (vm *VM) AppGossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error {
	// TODO: Handle gossiped orders and trades
	return nil
}

// AppRequest implements consensuscore.VM interface.
// It handles direct requests from peers.
func (vm *VM) AppRequest(
	ctx context.Context,
	nodeID ids.NodeID,
	requestID uint32,
	deadline time.Time,
	request []byte,
) error {
	// TODO: Handle peer requests (e.g., orderbook sync)
	return nil
}

// AppRequestFailed implements consensuscore.VM interface.
func (vm *VM) AppRequestFailed(ctx context.Context, nodeID ids.NodeID, requestID uint32, appErr *consensuscore.AppError) error {
	return nil
}

// AppResponse implements consensuscore.VM interface.
func (vm *VM) AppResponse(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error {
	return nil
}

// CrossChainAppRequest implements consensuscore.VM interface.
func (vm *VM) CrossChainAppRequest(
	ctx context.Context,
	chainID ids.ID,
	requestID uint32,
	deadline time.Time,
	request []byte,
) error {
	// TODO: Handle cross-chain requests via Warp
	return nil
}

// CrossChainAppRequestFailed implements consensuscore.VM interface.
func (vm *VM) CrossChainAppRequestFailed(ctx context.Context, chainID ids.ID, requestID uint32, appErr *consensuscore.AppError) error {
	return nil
}

// CrossChainAppResponse implements consensuscore.VM interface.
func (vm *VM) CrossChainAppResponse(ctx context.Context, chainID ids.ID, requestID uint32, response []byte) error {
	return nil
}

// NewCodec creates a new JSON codec for RPC.
func NewCodec() *Codec {
	return &Codec{}
}

// Codec implements gorilla/rpc codec interface.
type Codec struct{}

func (c *Codec) NewRequest(*http.Request) rpc.CodecRequest {
	return &CodecRequest{}
}

// CodecRequest implements rpc.CodecRequest
type CodecRequest struct{}

func (r *CodecRequest) Method() (string, error)                        { return "", nil }
func (r *CodecRequest) ReadRequest(interface{}) error                  { return nil }
func (r *CodecRequest) WriteResponse(http.ResponseWriter, interface{}) {}
func (r *CodecRequest) WriteError(http.ResponseWriter, int, error)     {}
