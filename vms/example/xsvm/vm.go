// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package xsvm

import (
	"context"
	"fmt"
	"net/http"

	"connectrpc.com/grpcreflect"
	"github.com/gorilla/rpc/v2"
	"github.com/luxfi/log"
	"github.com/luxfi/metric"

	"github.com/luxfi/cache"
	consensuscontext "github.com/luxfi/consensus/context"
	core "github.com/luxfi/consensus/core"
	"github.com/luxfi/consensus/core/interfaces"
	"github.com/luxfi/consensus/engine/chain"
	"github.com/luxfi/constants"
	"github.com/luxfi/database"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/p2p"
	"github.com/luxfi/utils/json"
	"github.com/luxfi/vm/connectproto/pb/xsvm/xsvmconnect"
	"github.com/luxfi/vm/vms/example/xsvm/api"
	"github.com/luxfi/vm/vms/example/xsvm/builder"
	"github.com/luxfi/vm/vms/example/xsvm/execute"
	"github.com/luxfi/vm/vms/example/xsvm/genesis"
	"github.com/luxfi/vm/vms/example/xsvm/state"
	"github.com/luxfi/warp"

	smblock "github.com/luxfi/consensus/engine/chain/block"
	xsblock "github.com/luxfi/vm/vms/example/xsvm/block"
	xschain "github.com/luxfi/vm/vms/example/xsvm/chain"
)

// TODO: Update xsvm to match current consensus ChainVM interface
// The consensus interface has evolved to use interface{} parameters
// var (
// 	_ smblock.ChainVM                      = (*VM)(nil)
// 	_ smblock.BuildBlockWithContextChainVM = (*VM)(nil)
// )

type VM struct {
	*p2p.Network

	chainContext *consensuscontext.Context
	db           database.Database
	genesis      *genesis.Genesis

	chain   xschain.Chain
	builder builder.Builder
}

func (vm *VM) Initialize(
	_ context.Context,
	chainContext *consensuscontext.Context,
	db database.Database,
	genesisBytes []byte,
	_ []byte,
	_ []byte,
	_ []*core.Fx,
	appSender warp.Sender,
) error {
	logger := chainContext.Log.(log.Logger)
	logger.Info("initializing xsvm",
		log.Stringer("version", Version),
	)

	metrics := metric.NewRegistry()
	if metricsReg, ok := chainContext.Metrics.(interface {
		Register(string, interface{}) error
	}); ok {
		if err := metricsReg.Register("p2p", metrics); err != nil {
			return err
		}
	}

	var err error
	vm.Network, err = p2p.NewNetwork(
		logger,
		appSender,
		metrics,
		"",
	)
	if err != nil {
		return err
	}

	// Allow signing of all warp messages. This is not typically safe, but is
	// allowed for this example.
	signatureCache := &cache.LRU[ids.ID, []byte]{Size: 100}
	// Cast WarpSigner directly to warp.Signer since both use external warp
	warpSigner := chainContext.WarpSigner.(warp.Signer)
	cachedHandler := warp.NewCachedSignatureHandler(
		signatureCache,
		xsvmVerifier{},
		warpSigner,
	)
	signatureHandler := warp.NewSignatureHandlerAdapter(cachedHandler)
	if err := vm.Network.AddHandler(warp.SignatureHandlerID, signatureHandler); err != nil {
		return err
	}

	vm.chainContext = chainContext
	vm.db = db
	g, err := genesis.Parse(genesisBytes)
	if err != nil {
		return fmt.Errorf("failed to parse genesis bytes: %w", err)
	}

	vdb := versiondb.New(vm.db)
	chainID := chainContext.ChainID
	if err := execute.Genesis(vdb, chainID, g); err != nil {
		return fmt.Errorf("failed to initialize genesis state: %w", err)
	}
	if err := vdb.Commit(); err != nil {
		return err
	}

	vm.genesis = g

	vm.chain, err = xschain.New(chainContext, vm.db)
	if err != nil {
		return fmt.Errorf("failed to initialize chain manager: %w", err)
	}

	vm.builder = builder.New(chainContext, vm.chain)

	logger.Info("initialized xsvm",
		log.Stringer("lastAcceptedID", vm.chain.LastAccepted()),
	)
	return nil
}

func (vm *VM) SetState(ctx context.Context, newState interfaces.State) error {
	// SetState receives the consensus engine, which we pass to the chain
	// The state parameter is actually the consensus engine
	if engine, ok := ctx.Value("engine").(chain.Engine); ok {
		vm.chain.SetChainState(engine)
	}
	return nil
}

// Connected overrides p2p.Network.Connected to match consensus interface
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion interface{}) error {
	// Convert interface{} back to the specific type p2p.Network expects
	return vm.Network.Connected(ctx, nodeID, nil)
}

func (vm *VM) Shutdown(context.Context) error {
	if vm.chainContext == nil {
		return nil
	}
	return vm.db.Close()
}

func (*VM) Version(context.Context) (string, error) {
	return Version.String(), nil
}

func (vm *VM) CreateHandlers(context.Context) (map[string]http.Handler, error) {
	server := rpc.NewServer()
	server.RegisterCodec(json.NewCodec(), "application/json")
	server.RegisterCodec(json.NewCodec(), "application/json;charset=UTF-8")
	jsonRPCAPI := api.NewServer(
		vm.chainContext,
		vm.genesis,
		vm.db,
		vm.chain,
		vm.builder,
	)
	return map[string]http.Handler{
		"": server,
	}, server.RegisterService(jsonRPCAPI, constants.XSVMName)
}

func (vm *VM) NewHTTPHandler(context.Context) (http.Handler, error) {
	mux := http.NewServeMux()

	reflectionPattern, reflectionHandler := grpcreflect.NewHandlerV1(
		grpcreflect.NewStaticReflector(xsvmconnect.PingName),
	)
	mux.Handle(reflectionPattern, reflectionHandler)

	pingService := &api.PingService{Log: vm.chainContext.Log.(log.Logger)}
	pingPath, pingHandler := xsvmconnect.NewPingHandler(pingService)
	mux.Handle(pingPath, pingHandler)

	return mux, nil
}

func (*VM) HealthCheck(context.Context) (interface{}, error) {
	return http.StatusOK, nil
}

func (vm *VM) GetBlock(_ context.Context, blkID ids.ID) (smblock.Block, error) {
	blk, err := vm.chain.GetBlock(blkID)
	if err != nil {
		return nil, err
	}
	return &blockWrapper{Block: blk}, nil
}

func (vm *VM) ParseBlock(_ context.Context, blkBytes []byte) (xschain.Block, error) {
	blk, err := xsblock.Parse(blkBytes)
	if err != nil {
		return nil, err
	}
	chainBlk, err := vm.chain.NewBlock(blk)
	if err != nil {
		return nil, err
	}
	return &blockWrapper{Block: chainBlk}, nil
}

func (vm *VM) WaitForEvent(ctx context.Context) (core.Message, error) {
	return vm.builder.WaitForEvent(ctx)
}

func (vm *VM) BuildBlock(ctx context.Context) (smblock.Block, error) {
	blk, err := vm.builder.BuildBlock(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &blockWrapper{Block: blk}, nil
}

func (vm *VM) SetPreference(_ context.Context, preferred ids.ID) error {
	vm.builder.SetPreference(preferred)
	return nil
}

func (vm *VM) LastAccepted(context.Context) (ids.ID, error) {
	return vm.chain.LastAccepted(), nil
}

func (vm *VM) BuildBlockWithContext(ctx context.Context, blockContext *smblock.Context) (smblock.Block, error) {
	blk, err := vm.builder.BuildBlock(ctx, blockContext)
	if err != nil {
		return nil, err
	}
	return &blockWrapper{Block: blk}, nil
}

func (vm *VM) GetBlockIDAtHeight(_ context.Context, height uint64) (ids.ID, error) {
	return state.GetBlockIDByHeight(vm.db, height)
}

// blockWrapper wraps an xsvm chain.Block to implement consensus block.Block
type blockWrapper struct {
	xschain.Block
}

// Status returns the uint8 status directly from the underlying block
func (b *blockWrapper) Status() uint8 {
	return b.Block.Status()
}
