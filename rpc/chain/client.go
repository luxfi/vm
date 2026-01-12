// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package chain provides RPC infrastructure for linear blockchain VMs (ChainVM).
// This implements the client for VMs that use blocks with single parents.
package chain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/luxfi/log"
	"github.com/luxfi/metric"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	consensuscontext "github.com/luxfi/consensus/context"
	"github.com/luxfi/consensus/engine"
	chainblock "github.com/luxfi/consensus/engine/chain/block"
	validators "github.com/luxfi/consensus/validator"
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	platformwarp "github.com/luxfi/protocol/p/warp"
	"github.com/luxfi/protocol/p/warp/gwarp"
	"github.com/luxfi/upgrade"
	"github.com/luxfi/resource"
	"github.com/luxfi/codec/wrappers"
	"github.com/luxfi/vm/api/metrics"
	"github.com/luxfi/vm/chains/atomic"
	"github.com/luxfi/vm/chains/atomic/gsharedmemory"
	"github.com/luxfi/vm/components/chain"
	"github.com/luxfi/vm/internal/database/rpcdb"
	"github.com/luxfi/vm/internal/ids/galiasreader"
	vmrpc "github.com/luxfi/vm/rpc"
	"github.com/luxfi/vm/rpc/appsender"
	"github.com/luxfi/vm/rpc/ghttp"
	"github.com/luxfi/vm/rpc/grpcutils"
	"github.com/luxfi/vm/rpc/gvalidators"
	"github.com/luxfi/vm/rpc/runtime"
	"github.com/luxfi/warp"

	grpc_metric "github.com/grpc-ecosystem/go-grpc-prometheus"
	aliasreaderpb "github.com/luxfi/node/proto/pb/aliasreader"
	appsenderpb "github.com/luxfi/node/proto/pb/appsender"
	httppb "github.com/luxfi/node/proto/pb/http"
	rpcdbpb "github.com/luxfi/node/proto/pb/rpcdb"
	sharedmemorypb "github.com/luxfi/node/proto/pb/sharedmemory"
	validatorstatepb "github.com/luxfi/node/proto/pb/validatorstate"
	vmpb "github.com/luxfi/node/proto/pb/vm"
	warppb "github.com/luxfi/node/proto/pb/warp"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

var (
	errUnsupportedFXs                       = errors.New("unsupported feature extensions")
	errBatchedParseBlockWrongNumberOfBlocks = errors.New("BatchedParseBlock returned different number of blocks than expected")

	_ chainblock.ChainVM                      = (*Client)(nil)
	_ chainblock.BuildBlockWithContextChainVM = (*Client)(nil)
	_ chainblock.BatchedChainVM               = (*Client)(nil)
	_ chainblock.StateSyncableVM              = (*Client)(nil)
	_ metric.Gatherer                         = (*Client)(nil)

	_ chainblock.Block             = (*BlockClient)(nil)
	_ chainblock.WithVerifyContext = (*BlockClient)(nil)

	_ chainblock.StateSummary = (*summaryClient)(nil)
)

// isNotImplementedError checks if a gRPC error indicates "not implemented"
func isNotImplementedError(err error) bool {
	if err == nil {
		return false
	}
	// Check for gRPC Unimplemented code
	if st, ok := status.FromError(err); ok {
		if st.Code() == codes.Unimplemented {
			return true
		}
		// Also check the message for "state syncable VM not implemented" or similar
		msg := st.Message()
		return strings.Contains(msg, "state syncable VM not implemented") ||
			strings.Contains(msg, "not implemented")
	}
	// Check for error message containing "not implemented"
	return strings.Contains(err.Error(), "state syncable VM not implemented") ||
		strings.Contains(err.Error(), "not implemented")
}

// Client is an implementation of a ChainVM that talks over RPC.
// This is the client-side of the RPC ChainVM interface, running in the node process.
type Client struct {
	*chain.State
	logger          log.Logger
	client          vmpb.VMClient
	runtime         runtime.Stopper
	pid             int
	processTracker  resource.ProcessTracker
	metricsGatherer metric.MultiGatherer

	sharedMemory         *gsharedmemory.Server
	bcLookup             *galiasreader.Server
	appSender            *appsender.Server
	validatorStateServer *gvalidators.Server
	warpSignerServer     *gwarp.Server

	serverCloser grpcutils.ServerCloser
	conns        []*grpc.ClientConn

	grpcServerMetrics *grpc_metric.ServerMetrics
}

// NewClient returns a ChainVM Client connected to a remote ChainVM Server.
func NewClient(
	clientConn *grpc.ClientConn,
	runtime runtime.Stopper,
	pid int,
	processTracker resource.ProcessTracker,
	metricsGatherer metrics.MultiGatherer,
	logger log.Logger,
) *Client {
	return &Client{
		client:          vmpb.NewVMClient(clientConn),
		runtime:         runtime,
		pid:             pid,
		processTracker:  processTracker,
		metricsGatherer: metricsGatherer,
		conns:           []*grpc.ClientConn{clientConn},
		logger:          logger,
	}
}

// Runtime returns the runtime Stopper for managing the VM subprocess.
// This allows callers to stop the subprocess when needed.
func (vm *Client) Runtime() runtime.Stopper {
	return vm.runtime
}

func (vm *Client) Initialize(
	ctx context.Context,
	chainCtxIface interface{},
	dbIface interface{},
	genesisBytes []byte,
	upgradeBytes []byte,
	configBytes []byte,
	msgChan interface{},
	fxs []interface{},
	appSender interface{},
) error {
	// Type assert to get concrete types
	var consensusCtx *consensuscontext.Context
	if cc, ok := chainCtxIface.(*chainblock.ChainContext); ok && cc != nil {
		consensusCtx = cc.Context
		if consensusCtx != nil {
			ctx = consensuscontext.WithIDs(ctx, consensuscontext.IDs{
				NetworkID: consensusCtx.NetworkID,
				ChainID:   consensusCtx.ChainID,
				NodeID:    consensusCtx.NodeID,
				PublicKey: consensusCtx.PublicKey,
			})
		}
	}

	// Get the current database from the manager
	var db database.Database
	if currentDB, ok := dbIface.(interface{ Current() database.Database }); ok {
		db = currentDB.Current()
	} else if directDB, ok := dbIface.(database.Database); ok {
		// Handle direct database types (e.g., *prefixdb.Database)
		db = directDB
	}
	if db == nil {
		return fmt.Errorf("unable to get database from manager: dbIface type is %T", dbIface)
	}
	if len(fxs) != 0 {
		return errUnsupportedFXs
	}

	// Convert interface{} parameters to concrete types
	// Handle both *Context and *consensuscontext.Context
	var chainCtx *vmrpc.Context
	switch ctx := chainCtxIface.(type) {
	case *vmrpc.Context:
		chainCtx = ctx
	case *consensuscontext.Context:
		// Convert consensus context to chain context
		chainCtx = &vmrpc.Context{
			NetworkID:    ctx.NetworkID,
			NetID:        ctx.ChainID,
			ChainID:      ctx.ChainID,
			NodeID:       ctx.NodeID,
			XChainID:     ctx.XChainID,
			CChainID:     ctx.CChainID,
			LUXAssetID:   ctx.XAssetID, // Use XAssetID as the primary asset
			ChainDataDir: ctx.ChainDataDir,
		}
		// Handle type conversions for interface fields
		if ctx.Log != nil {
			if l, ok := ctx.Log.(log.Logger); ok {
				chainCtx.Log = l
			}
		}
		if ctx.SharedMemory != nil {
			if sm, ok := ctx.SharedMemory.(atomic.SharedMemory); ok {
				chainCtx.SharedMemory = sm
			}
		}
		if ctx.Metrics != nil {
			if m, ok := ctx.Metrics.(metrics.MultiGatherer); ok {
				chainCtx.Metrics = m
			}
		}
		if ctx.ValidatorState != nil {
			if vs, ok := ctx.ValidatorState.(validators.State); ok {
				chainCtx.ValidatorState = vs
			}
		}
		// BCLookup conversion - critical for plugin VM alias resolution
		if ctx.BCLookup != nil {
			// Try direct type assertion to ids.AliaserReader first
			if bcl, ok := ctx.BCLookup.(ids.AliaserReader); ok {
				chainCtx.BCLookup = bcl
			} else if bcl, ok := ctx.BCLookup.(consensuscontext.BCLookup); ok {
				// Wrap the consensus context BCLookup interface
				chainCtx.BCLookup = &bcLookupWrapper{bc: bcl}
			} else {
				// BCLookup is set but not a recognized type - log warning but continue
				if !vm.logger.IsZero() {
					vm.logger.Warn("BCLookup has unrecognized type, alias resolution may fail",
						log.String("type", fmt.Sprintf("%T", ctx.BCLookup)))
				}
			}
		}
		// WarpSigner conversion - for BLS signing of warp messages
		if ctx.WarpSigner != nil {
			if ws, ok := ctx.WarpSigner.(platformwarp.Signer); ok {
				chainCtx.WarpSigner = ws
			}
		}
		// PublicKey conversion from []byte
		if len(ctx.PublicKey) > 0 {
			pk, err := bls.PublicKeyFromCompressedBytes(ctx.PublicKey)
			if err == nil {
				chainCtx.PublicKey = pk
			}
		}
		// NetworkUpgrades conversion - critical for plugin VMs
		if ctx.NetworkUpgrades != nil {
			if upgrades, ok := ctx.NetworkUpgrades.(upgrade.Config); ok {
				chainCtx.NetworkUpgrades = upgrades
			} else if upgradesPtr, ok := ctx.NetworkUpgrades.(*upgrade.Config); ok && upgradesPtr != nil {
				chainCtx.NetworkUpgrades = *upgradesPtr
			} else {
				// Fall back to network-specific defaults
				chainCtx.NetworkUpgrades = upgrade.GetConfig(ctx.NetworkID)
				if !vm.logger.IsZero() {
					vm.logger.Warn("NetworkUpgrades has unrecognized type, using network defaults",
						log.String("type", fmt.Sprintf("%T", ctx.NetworkUpgrades)),
						log.Uint32("networkID", ctx.NetworkID))
				}
			}
		} else {
			// No NetworkUpgrades provided, use network-specific defaults
			chainCtx.NetworkUpgrades = upgrade.GetConfig(ctx.NetworkID)
		}
	default:
		return fmt.Errorf("invalid chain context type: expected *vmrpc.Context or *consensuscontext.Context, got %T", chainCtxIface)
	}

	// Convert appSender to concrete type
	var appSenderConcrete warp.Sender
	if appSender != nil {
		appSenderConcrete = appSender.(warp.Sender)
	}

	var primaryAlias string
	if chainCtx.BCLookup != nil {
		var err error
		primaryAlias, err = chainCtx.BCLookup.PrimaryAlias(chainCtx.ChainID)
		if err != nil {
			// If fetching the alias fails, we default to the chain's ID
			primaryAlias = chainCtx.ChainID.String()
		}
	} else {
		primaryAlias = chainCtx.ChainID.String()
	}

	// Register metrics
	serverReg, err := metric.MakeAndRegister(
		vm.metricsGatherer,
		primaryAlias,
	)
	if err != nil {
		return err
	}
	vm.grpcServerMetrics = grpc_metric.NewServerMetrics()
	if err := serverReg.Register(vm.grpcServerMetrics); err != nil {
		return err
	}

	// Initialize the database
	dbServerListener, err := grpcutils.NewListener()
	if err != nil {
		return err
	}
	dbServerAddr := dbServerListener.Addr().String()

	go grpcutils.Serve(dbServerListener, vm.newDBServer(db))
	if !chainCtx.Log.IsZero() {
		chainCtx.Log.Info("grpc: serving database",
			log.String("address", dbServerAddr),
		)
	}

	if chainCtx.SharedMemory != nil {
		vm.sharedMemory = gsharedmemory.NewServer(chainCtx.SharedMemory, db)
	}
	if chainCtx.BCLookup != nil {
		vm.bcLookup = galiasreader.NewServer(chainCtx.BCLookup)
	} else if !chainCtx.Log.IsZero() {
		chainCtx.Log.Warn("BCLookup is nil - chain alias resolution will not work for plugin VM")
	}
	if appSenderConcrete != nil {
		vm.appSender = appsender.NewServer(appSenderConcrete)
	}
	if chainCtx.ValidatorState != nil {
		vm.validatorStateServer = gvalidators.NewServer(chainCtx.ValidatorState)
	}
	if chainCtx.WarpSigner != nil {
		vm.warpSignerServer = gwarp.NewServer(chainCtx.WarpSigner)
	}

	serverListener, err := grpcutils.NewListener()
	if err != nil {
		return err
	}
	serverAddr := serverListener.Addr().String()

	go grpcutils.Serve(serverListener, vm.newInitServer())
	if !chainCtx.Log.IsZero() {
		chainCtx.Log.Info("grpc: serving vm services",
			log.String("address", serverAddr),
		)
	}

	networkUpgrades := &vmpb.NetworkUpgrades{
		ApricotPhase_1Time:            grpcutils.TimestampFromTime(chainCtx.NetworkUpgrades.ApricotPhase1Time),
		ApricotPhase_2Time:            grpcutils.TimestampFromTime(chainCtx.NetworkUpgrades.ApricotPhase2Time),
		ApricotPhase_3Time:            grpcutils.TimestampFromTime(chainCtx.NetworkUpgrades.ApricotPhase3Time),
		ApricotPhase_4Time:            grpcutils.TimestampFromTime(chainCtx.NetworkUpgrades.ApricotPhase4Time),
		ApricotPhase_4MinPChainHeight: chainCtx.NetworkUpgrades.ApricotPhase4MinPChainHeight,
		ApricotPhase_5Time:            grpcutils.TimestampFromTime(chainCtx.NetworkUpgrades.ApricotPhase5Time),
		ApricotPhasePre_6Time:         grpcutils.TimestampFromTime(chainCtx.NetworkUpgrades.ApricotPhasePre6Time),
		ApricotPhase_6Time:            grpcutils.TimestampFromTime(chainCtx.NetworkUpgrades.ApricotPhase6Time),
		ApricotPhasePost_6Time:        grpcutils.TimestampFromTime(chainCtx.NetworkUpgrades.ApricotPhasePost6Time),
		BanffTime:                     grpcutils.TimestampFromTime(chainCtx.NetworkUpgrades.BanffTime),
		CortinaTime:                   grpcutils.TimestampFromTime(chainCtx.NetworkUpgrades.CortinaTime),
		CortinaXChainStopVertexId:     chainCtx.NetworkUpgrades.CortinaXChainStopVertexID[:],
		DurangoTime:                   grpcutils.TimestampFromTime(chainCtx.NetworkUpgrades.DurangoTime),
		EtnaTime:                      grpcutils.TimestampFromTime(chainCtx.NetworkUpgrades.EtnaTime),
		FortunaTime:                   grpcutils.TimestampFromTime(chainCtx.NetworkUpgrades.FortunaTime),
		GraniteTime:                   grpcutils.TimestampFromTime(chainCtx.NetworkUpgrades.GraniteTime),
	}

	var publicKeyBytes []byte
	if chainCtx.PublicKey != nil {
		publicKeyBytes = bls.PublicKeyToCompressedBytes(chainCtx.PublicKey)
	}

	resp, err := vm.client.Initialize(ctx, &vmpb.InitializeRequest{
		NetworkId:       chainCtx.NetworkID,
		ChainId:         chainCtx.ChainID[:],
		NodeId:          chainCtx.NodeID.Bytes(),
		PublicKey:       publicKeyBytes,
		NetworkUpgrades: networkUpgrades,
		XChainId:        chainCtx.XChainID[:],
		CChainId:        chainCtx.CChainID[:],
		LuxAssetId:      chainCtx.LUXAssetID[:],
		ChainDataDir:    chainCtx.ChainDataDir,
		GenesisBytes:    genesisBytes,
		UpgradeBytes:    upgradeBytes,
		ConfigBytes:     configBytes,
		DbServerAddr:    dbServerAddr,
		ServerAddr:      serverAddr,
	})
	if err != nil {
		return err
	}

	if chainCtx.Metrics != nil {
		// Use "vm" prefix to avoid conflicts with the chain ID prefix already registered
		if err := chainCtx.Metrics.Register("vm", vm); err != nil {
			return err
		}
	}

	id, err := ids.ToID(resp.LastAcceptedId)
	if err != nil {
		return err
	}
	parentID, err := ids.ToID(resp.LastAcceptedParentId)
	if err != nil {
		return err
	}

	time, err := grpcutils.TimestampAsTime(resp.Timestamp)
	if err != nil {
		return err
	}

	// We don't need to check whether this is a block.WithVerifyContext because
	// we'll never Verify this block.
	lastAcceptedBlk := &BlockClient{
		VM:       vm,
		ID_:      id,
		ParentID_: parentID,
		Bytes_:   resp.Bytes,
		Height_:  resp.Height,
		Time_:    time,
	}

	// Initialize the State if not already done
	if vm.State == nil {
		wrappedBlk := &protocolBlockWrapper{BlockClient: lastAcceptedBlk}
		vm.State = chain.NewState(&chain.Config{
			DecidedCacheSize:      1024,
			MissingCacheSize:      1024,
			UnverifiedCacheSize:   64,
			BytesToIDCacheSize:    512,
			LastAcceptedBlock:     wrappedBlk,
			GetBlock:              vm.GetBlock,
			UnmarshalBlock:        vm.ParseBlock,
			BatchedUnmarshalBlock: vm.BatchedParseBlock,
			BuildBlock:            vm.BuildBlock,
		})
	}

	// Client doesn't need a caching layer - it's just an RPC client
	// The caching happens on the server side
	return vm.SetLastAcceptedBlock(&protocolBlockWrapper{BlockClient: lastAcceptedBlk})
}

func (vm *Client) newDBServer(db database.Database) *grpc.Server {
	server := grpcutils.NewServer(
		grpcutils.WithUnaryInterceptor(vm.grpcServerMetrics.UnaryServerInterceptor()),
		grpcutils.WithStreamInterceptor(vm.grpcServerMetrics.StreamServerInterceptor()),
	)

	// See https://github.com/grpc/grpc/blob/master/doc/health-checking.md
	grpcHealth := health.NewServer()
	grpcHealth.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	vm.serverCloser.Add(server)

	// Register services
	rpcdbpb.RegisterDatabaseServer(server, rpcdb.NewServer(db))
	healthpb.RegisterHealthServer(server, grpcHealth)

	// Ensure metric counters are zeroed on restart
	grpc_metric.Register(server)

	return server
}

func (vm *Client) newInitServer() *grpc.Server {
	server := grpcutils.NewServer(
		grpcutils.WithUnaryInterceptor(vm.grpcServerMetrics.UnaryServerInterceptor()),
		grpcutils.WithStreamInterceptor(vm.grpcServerMetrics.StreamServerInterceptor()),
	)

	// See https://github.com/grpc/grpc/blob/master/doc/health-checking.md
	grpcHealth := health.NewServer()
	grpcHealth.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	vm.serverCloser.Add(server)

	// Register services
	sharedmemorypb.RegisterSharedMemoryServer(server, vm.sharedMemory)
	aliasreaderpb.RegisterAliasReaderServer(server, vm.bcLookup)
	appsenderpb.RegisterAppSenderServer(server, vm.appSender)
	healthpb.RegisterHealthServer(server, grpcHealth)
	validatorstatepb.RegisterValidatorStateServer(server, vm.validatorStateServer)
	warppb.RegisterSignerServer(server, vm.warpSignerServer)

	// Ensure metric counters are zeroed on restart
	grpc_metric.Register(server)

	return server
}

func (vm *Client) SetState(ctx context.Context, state uint32) error {
	resp, err := vm.client.SetState(ctx, &vmpb.SetStateRequest{
		State: vmpb.State(state),
	})
	if err != nil {
		return err
	}

	id, err := ids.ToID(resp.LastAcceptedId)
	if err != nil {
		return err
	}

	parentID, err := ids.ToID(resp.LastAcceptedParentId)
	if err != nil {
		return err
	}

	time, err := grpcutils.TimestampAsTime(resp.Timestamp)
	if err != nil {
		return err
	}

	// We don't need to check whether this is a block.WithVerifyContext because
	// we'll never Verify this block.
	return vm.SetLastAcceptedBlock(&protocolBlockWrapper{BlockClient: &BlockClient{
		VM:       vm,
		ID_:      id,
		ParentID_: parentID,
		Bytes_:   resp.Bytes,
		Height_:  resp.Height,
		Time_:    time,
	}})
}

func (vm *Client) Shutdown(ctx context.Context) error {
	errs := wrappers.Errs{}
	_, err := vm.client.Shutdown(ctx, &emptypb.Empty{})
	errs.Add(err)

	vm.serverCloser.Stop()
	for _, conn := range vm.conns {
		errs.Add(conn.Close())
	}

	vm.runtime.Stop(ctx)

	vm.processTracker.UntrackProcess(vm.pid)
	return errs.Err
}

func (vm *Client) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	resp, err := vm.client.CreateHandlers(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	handlers := make(map[string]http.Handler, len(resp.Handlers))
	for _, handler := range resp.Handlers {
		clientConn, err := grpcutils.Dial(handler.ServerAddr)
		if err != nil {
			return nil, err
		}

		vm.conns = append(vm.conns, clientConn)
		handlers[handler.Prefix] = ghttp.NewClient(httppb.NewHTTPClient(clientConn), vm.logger)
	}
	return handlers, nil
}

func (vm *Client) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion interface{}) error {
	// Connected is not part of block.ChainVM interface - no-op
	_ = nodeID
	_ = nodeVersion
	return nil
}

func (vm *Client) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	// Disconnected is not part of block.ChainVM interface - no-op
	_ = nodeID
	return nil
}

// If the underlying VM doesn't actually implement this method, its [BuildBlock]
// method will be called instead.
func (vm *Client) buildBlockWithContext(ctx context.Context, blockCtx *chainblock.Context) (chainblock.Block, error) {
	resp, err := vm.client.BuildBlock(ctx, &vmpb.BuildBlockRequest{
		PChainHeight: &blockCtx.PChainHeight,
	})
	if err != nil {
		return nil, err
	}
	blk, err := vm.newBlockFromBuildBlock(resp)
	if err != nil {
		return nil, err
	}
	return &componentsBlockWrapper{BlockClient: blk}, nil
}

func (vm *Client) buildBlock(ctx context.Context) (chainblock.Block, error) {
	resp, err := vm.client.BuildBlock(ctx, &vmpb.BuildBlockRequest{})
	if err != nil {
		return nil, err
	}
	blk, err := vm.newBlockFromBuildBlock(resp)
	if err != nil {
		return nil, err
	}
	return &componentsBlockWrapper{BlockClient: blk}, nil
}

func (vm *Client) parseBlock(ctx context.Context, bytes []byte) (chainblock.Block, error) {
	resp, err := vm.client.ParseBlock(ctx, &vmpb.ParseBlockRequest{
		Bytes: bytes,
	})
	if err != nil {
		return nil, err
	}

	id, err := ids.ToID(resp.Id)
	if err != nil {
		return nil, err
	}

	parentID, err := ids.ToID(resp.ParentId)
	if err != nil {
		return nil, err
	}

	time, err := grpcutils.TimestampAsTime(resp.Timestamp)
	if err != nil {
		return nil, err
	}
	return &componentsBlockWrapper{BlockClient: &BlockClient{
		VM:                  vm,
		ID_:                 id,
		ParentID_:           parentID,
		Bytes_:              bytes,
		Height_:             resp.Height,
		Time_:               time,
		ShouldVerifyWithCtx: resp.VerifyWithContext,
	}}, nil
}

func (vm *Client) getBlock(ctx context.Context, blkID ids.ID) (chainblock.Block, error) {
	resp, err := vm.client.GetBlock(ctx, &vmpb.GetBlockRequest{
		Id: blkID[:],
	})
	if err != nil {
		return nil, err
	}
	if errEnum := resp.Err; errEnum != vmpb.Error_ERROR_UNSPECIFIED {
		return nil, errEnumToError[errEnum]
	}

	parentID, err := ids.ToID(resp.ParentId)
	if err != nil {
		return nil, err
	}

	time, err := grpcutils.TimestampAsTime(resp.Timestamp)
	if err != nil {
		return nil, err
	}
	return &componentsBlockWrapper{BlockClient: &BlockClient{
		VM:                  vm,
		ID_:                 blkID,
		ParentID_:           parentID,
		Bytes_:              resp.Bytes,
		Height_:             resp.Height,
		Time_:               time,
		ShouldVerifyWithCtx: resp.VerifyWithContext,
	}}, nil
}

func (vm *Client) SetPreference(ctx context.Context, blkID ids.ID) error {
	_, err := vm.client.SetPreference(ctx, &vmpb.SetPreferenceRequest{
		Id: blkID[:],
	})
	return err
}

func (vm *Client) HealthCheck(ctx context.Context) (interface{}, error) {
	// HealthCheck is a special case, where we want to fail fast instead of block.
	failFast := grpc.WaitForReady(false)
	health, err := vm.client.Health(ctx, &emptypb.Empty{}, failFast)
	if err != nil {
		return nil, fmt.Errorf("health check failed: %w", err)
	}

	return json.RawMessage(health.Details), nil
}

func (vm *Client) Version(ctx context.Context) (string, error) {
	resp, err := vm.client.Version(ctx, &emptypb.Empty{})
	if err != nil {
		return "", err
	}
	return resp.Version, nil
}

func (vm *Client) AppRequest(ctx context.Context, nodeID ids.NodeID, requestID uint32, deadline time.Time, request []byte) error {
	_, err := vm.client.AppRequest(
		ctx,
		&vmpb.AppRequestMsg{
			NodeId:    nodeID.Bytes(),
			RequestId: requestID,
			Request:   request,
			Deadline:  grpcutils.TimestampFromTime(deadline),
		},
	)
	return err
}

func (vm *Client) AppResponse(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error {
	_, err := vm.client.AppResponse(
		ctx,
		&vmpb.AppResponseMsg{
			NodeId:    nodeID.Bytes(),
			RequestId: requestID,
			Response:  response,
		},
	)
	return err
}

func (vm *Client) AppRequestFailed(ctx context.Context, nodeID ids.NodeID, requestID uint32, appErr *warp.Error) error {
	msg := &vmpb.AppRequestFailedMsg{
		NodeId:       nodeID.Bytes(),
		RequestId:    requestID,
		ErrorCode:    appErr.Code,
		ErrorMessage: appErr.Message,
	}

	_, err := vm.client.AppRequestFailed(ctx, msg)
	return err
}

func (vm *Client) AppGossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error {
	_, err := vm.client.AppGossip(
		ctx,
		&vmpb.AppGossipMsg{
			NodeId: nodeID.Bytes(),
			Msg:    msg,
		},
	)
	return err
}

func (vm *Client) Gather() ([]*metric.MetricFamily, error) {
	resp, err := vm.client.Gather(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return metric.DTOToNative(resp.MetricFamilies), nil
}

func (vm *Client) GetAncestors(
	ctx context.Context,
	blkID ids.ID,
	maxBlocksNum int,
	maxBlocksSize int,
	maxBlocksRetrivalTime time.Duration,
) ([][]byte, error) {
	resp, err := vm.client.GetAncestors(ctx, &vmpb.GetAncestorsRequest{
		BlkId:                 blkID[:],
		MaxBlocksNum:          int32(maxBlocksNum),
		MaxBlocksSize:         int32(maxBlocksSize),
		MaxBlocksRetrivalTime: int64(maxBlocksRetrivalTime),
	})
	if err != nil {
		return nil, err
	}
	return resp.BlksBytes, nil
}

func (vm *Client) batchedParseBlock(ctx context.Context, blksBytes [][]byte) ([]chainblock.Block, error) {
	resp, err := vm.client.BatchedParseBlock(ctx, &vmpb.BatchedParseBlockRequest{
		Request: blksBytes,
	})
	if err != nil {
		return nil, err
	}
	if len(blksBytes) != len(resp.Response) {
		return nil, errBatchedParseBlockWrongNumberOfBlocks
	}

	res := make([]chainblock.Block, 0, len(blksBytes))
	for idx, blkResp := range resp.Response {
		id, err := ids.ToID(blkResp.Id)
		if err != nil {
			return nil, err
		}

		parentID, err := ids.ToID(blkResp.ParentId)
		if err != nil {
			return nil, err
		}

		time, err := grpcutils.TimestampAsTime(blkResp.Timestamp)
		if err != nil {
			return nil, err
		}

		res = append(res, &componentsBlockWrapper{BlockClient: &BlockClient{
			VM:                  vm,
			ID_:                 id,
			ParentID_:           parentID,
			Bytes_:              blksBytes[idx],
			Height_:             blkResp.Height,
			Time_:               time,
			ShouldVerifyWithCtx: blkResp.VerifyWithContext,
		}})
	}

	return res, nil
}

func (vm *Client) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	resp, err := vm.client.GetBlockIDAtHeight(
		ctx,
		&vmpb.GetBlockIDAtHeightRequest{Height: height},
	)
	if err != nil {
		return ids.Empty, err
	}
	if errEnum := resp.Err; errEnum != vmpb.Error_ERROR_UNSPECIFIED {
		return ids.Empty, errEnumToError[errEnum]
	}
	return ids.ToID(resp.BlkId)
}

// GetChainID implements block.ChainVM.
func (vm *Client) GetChainID(ctx context.Context) (ids.ID, error) {
	// For now return empty ID - will be implemented later
	return ids.Empty, nil
}

func (vm *Client) StateSyncEnabled(ctx context.Context) (bool, error) {
	resp, err := vm.client.StateSyncEnabled(ctx, &emptypb.Empty{})
	if err != nil {
		// Check if this is the "not implemented" gRPC error
		// StateSyncEnabled returns (false, nil) instead of error when not implemented
		if isNotImplementedError(err) {
			return false, nil
		}
		return false, err
	}
	err = errEnumToError[resp.Err]
	if err == chainblock.ErrStateSyncableVMNotImplemented {
		return false, nil
	}
	return resp.Enabled, err
}

func (vm *Client) GetOngoingSyncStateSummary(ctx context.Context) (chainblock.StateSummary, error) {
	resp, err := vm.client.GetOngoingSyncStateSummary(ctx, &emptypb.Empty{})
	if err != nil {
		// Check if this is the "not implemented" gRPC error
		if isNotImplementedError(err) {
			return nil, chainblock.ErrStateSyncableVMNotImplemented
		}
		return nil, err
	}
	if errEnum := resp.Err; errEnum != vmpb.Error_ERROR_UNSPECIFIED {
		return nil, errEnumToError[errEnum]
	}

	summaryID, err := ids.ToID(resp.Id)
	return &summaryClient{
		vm:     vm,
		id:     summaryID,
		height: resp.Height,
		bytes:  resp.Bytes,
	}, err
}

func (vm *Client) GetLastStateSummary(ctx context.Context) (chainblock.StateSummary, error) {
	resp, err := vm.client.GetLastStateSummary(ctx, &emptypb.Empty{})
	if err != nil {
		// Check if this is the "not implemented" gRPC error
		if isNotImplementedError(err) {
			return nil, chainblock.ErrStateSyncableVMNotImplemented
		}
		return nil, err
	}
	if errEnum := resp.Err; errEnum != vmpb.Error_ERROR_UNSPECIFIED {
		return nil, errEnumToError[errEnum]
	}

	summaryID, err := ids.ToID(resp.Id)
	return &summaryClient{
		vm:     vm,
		id:     summaryID,
		height: resp.Height,
		bytes:  resp.Bytes,
	}, err
}

func (vm *Client) ParseStateSummary(ctx context.Context, summaryBytes []byte) (chainblock.StateSummary, error) {
	resp, err := vm.client.ParseStateSummary(
		ctx,
		&vmpb.ParseStateSummaryRequest{
			Bytes: summaryBytes,
		},
	)
	if err != nil {
		// Check if this is the "not implemented" gRPC error
		if isNotImplementedError(err) {
			return nil, chainblock.ErrStateSyncableVMNotImplemented
		}
		return nil, err
	}
	if errEnum := resp.Err; errEnum != vmpb.Error_ERROR_UNSPECIFIED {
		return nil, errEnumToError[errEnum]
	}

	summaryID, err := ids.ToID(resp.Id)
	return &summaryClient{
		vm:     vm,
		id:     summaryID,
		height: resp.Height,
		bytes:  summaryBytes,
	}, err
}

func (vm *Client) GetStateSummary(ctx context.Context, summaryHeight uint64) (chainblock.StateSummary, error) {
	resp, err := vm.client.GetStateSummary(
		ctx,
		&vmpb.GetStateSummaryRequest{
			Height: summaryHeight,
		},
	)
	if err != nil {
		// Check if this is the "not implemented" gRPC error
		if isNotImplementedError(err) {
			return nil, chainblock.ErrStateSyncableVMNotImplemented
		}
		return nil, err
	}
	if errEnum := resp.Err; errEnum != vmpb.Error_ERROR_UNSPECIFIED {
		return nil, errEnumToError[errEnum]
	}

	summaryID, err := ids.ToID(resp.Id)
	return &summaryClient{
		vm:     vm,
		id:     summaryID,
		height: summaryHeight,
		bytes:  resp.Bytes,
	}, err
}

func (vm *Client) newBlockFromBuildBlock(resp *vmpb.BuildBlockResponse) (*BlockClient, error) {
	id, err := ids.ToID(resp.Id)
	if err != nil {
		return nil, err
	}

	parentID, err := ids.ToID(resp.ParentId)
	if err != nil {
		return nil, err
	}

	time, err := grpcutils.TimestampAsTime(resp.Timestamp)
	return &BlockClient{
		VM:                  vm,
		ID_:                 id,
		ParentID_:           parentID,
		Bytes_:              resp.Bytes,
		Height_:             resp.Height,
		Time_:               time,
		ShouldVerifyWithCtx: resp.VerifyWithContext,
	}, err
}

// WaitForEvent implements the VM interface
func (vm *Client) WaitForEvent(ctx context.Context) (interface{}, error) {
	// The RPC VM client doesn't directly handle events,
	// it relies on the server-side VM for event handling
	<-ctx.Done()
	return engine.PendingTxs, ctx.Err()
}

// NewHTTPHandler implements the VM interface
func (vm *Client) NewHTTPHandler(ctx context.Context) (interface{}, error) {
	// RPC VM uses CreateHandlers instead of a single handler
	return nil, nil
}

// BuildBlock implements the block.ChainVM interface
func (vm *Client) BuildBlock(ctx context.Context) (chainblock.Block, error) {
	innerBlk, err := vm.buildBlock(ctx)
	if err != nil {
		return nil, err
	}
	// Convert chainblock.Block to block.Block through wrapper
	return &chainBlockWrapper{innerBlk}, nil
}

// BuildBlockWithContext implements the block.BuildBlockWithContextChainVM interface
func (vm *Client) BuildBlockWithContext(ctx context.Context, blockCtx *chainblock.Context) (chainblock.Block, error) {
	innerBlk, err := vm.buildBlockWithContext(ctx, blockCtx)
	if err != nil {
		return nil, err
	}
	// Convert chainblock.Block to block.Block through wrapper
	return &chainBlockWrapper{innerBlk}, nil
}

// ParseBlock implements the block.ChainVM interface
func (vm *Client) ParseBlock(ctx context.Context, bytes []byte) (chainblock.Block, error) {
	innerBlk, err := vm.parseBlock(ctx, bytes)
	if err != nil {
		return nil, err
	}
	// Convert chainblock.Block to block.Block through wrapper
	return &chainBlockWrapper{innerBlk}, nil
}

// GetBlock implements the block.ChainVM interface
func (vm *Client) GetBlock(ctx context.Context, id ids.ID) (chainblock.Block, error) {
	innerBlk, err := vm.getBlock(ctx, id)
	if err != nil {
		return nil, err
	}
	// Convert chainblock.Block to block.Block through wrapper
	return &chainBlockWrapper{innerBlk}, nil
}

// LastAccepted implements the block.ChainVM interface
func (vm *Client) LastAccepted(ctx context.Context) (ids.ID, error) {
	lastAcceptedBlk := vm.LastAcceptedBlock()
	return lastAcceptedBlk.ID(), nil
}

// BatchedParseBlock implements the block.BatchedChainVM interface
func (vm *Client) BatchedParseBlock(ctx context.Context, blks [][]byte) ([]chainblock.Block, error) {
	innerBlks, err := vm.batchedParseBlock(ctx, blks)
	if err != nil {
		return nil, err
	}
	// Convert []chainblock.Block to []chainblock.Block
	result := make([]chainblock.Block, len(innerBlks))
	for i, blk := range innerBlks {
		result[i] = &chainBlockWrapper{blk}
	}
	return result, nil
}

// BlockClient is the client-side representation of a block received from the server.
// This type is exported for use by adapter packages that need to wrap blocks.
type BlockClient struct {
	VM *Client

	ID_                 ids.ID
	ParentID_           ids.ID
	Bytes_              []byte
	Height_             uint64
	Time_               time.Time
	ShouldVerifyWithCtx bool
}

func (b *BlockClient) ID() ids.ID {
	return b.ID_
}

// EpochBit returns the epoch bit for FPC
func (b *BlockClient) EpochBit() bool {
	// RPC blocks don't support epoch bits yet
	return false
}

// FPCVotes returns embedded fast-path vote references
func (b *BlockClient) FPCVotes() [][]byte {
	// RPC blocks don't support FPC votes yet
	return nil
}

func (b *BlockClient) Accept(ctx context.Context) error {
	_, err := b.VM.client.BlockAccept(ctx, &vmpb.BlockAcceptRequest{
		Id: b.ID_[:],
	})
	return err
}

func (b *BlockClient) Reject(ctx context.Context) error {
	_, err := b.VM.client.BlockReject(ctx, &vmpb.BlockRejectRequest{
		Id: b.ID_[:],
	})
	return err
}

func (b *BlockClient) Parent() ids.ID {
	return b.ParentID_
}

// ParentID implements block.Block
func (b *BlockClient) ParentID() ids.ID {
	return b.ParentID_
}

func (b *BlockClient) Verify(ctx context.Context) error {
	resp, err := b.VM.client.BlockVerify(ctx, &vmpb.BlockVerifyRequest{
		Bytes: b.Bytes_,
	})
	if err != nil {
		return err
	}

	b.Time_, err = grpcutils.TimestampAsTime(resp.Timestamp)
	return err
}

func (b *BlockClient) Bytes() []byte {
	return b.Bytes_
}

func (b *BlockClient) Height() uint64 {
	return b.Height_
}

func (b *BlockClient) Timestamp() time.Time {
	return b.Time_
}

// Status returns the block status as uint8
func (b *BlockClient) Status() uint8 {
	return 0 // Status tracking is handled by the VM
}

func (b *BlockClient) ShouldVerifyWithContext(context.Context) (bool, error) {
	return b.ShouldVerifyWithCtx, nil
}

func (b *BlockClient) VerifyWithContext(ctx context.Context, blockCtx *chainblock.Context) error {
	resp, err := b.VM.client.BlockVerify(ctx, &vmpb.BlockVerifyRequest{
		Bytes:        b.Bytes_,
		PChainHeight: &blockCtx.PChainHeight,
	})
	if err != nil {
		return err
	}

	b.Time_, err = grpcutils.TimestampAsTime(resp.Timestamp)
	return err
}

// summaryClient is the client-side representation of a state summary.
type summaryClient struct {
	vm *Client

	id     ids.ID
	height uint64
	bytes  []byte
}

func (s *summaryClient) ID() ids.ID {
	return s.id
}

func (s *summaryClient) Height() uint64 {
	return s.height
}

func (s *summaryClient) Bytes() []byte {
	return s.bytes
}

func (s *summaryClient) Accept(ctx context.Context) (chainblock.StateSyncMode, error) {
	resp, err := s.vm.client.StateSummaryAccept(
		ctx,
		&vmpb.StateSummaryAcceptRequest{
			Bytes: s.bytes,
		},
	)
	if err != nil {
		return chainblock.StateSyncSkipped, err
	}
	return chainblock.StateSyncMode(resp.Mode), errEnumToError[resp.Err]
}

// chainBlockWrapper wraps a chainblock.Block to implement block.Block
type chainBlockWrapper struct {
	chainblock.Block
}

// Status implements block.Block - returns uint8
func (b *chainBlockWrapper) Status() uint8 {
	// chainblock.Block already has Status() that returns uint8
	return b.Block.Status()
}

// Accept implements block.Block
func (b *chainBlockWrapper) Accept(ctx context.Context) error {
	// Forward to embedded chainblock.Block
	return b.Block.Accept(ctx)
}

// Reject implements block.Block
func (b *chainBlockWrapper) Reject(ctx context.Context) error {
	// Forward to embedded chainblock.Block
	return b.Block.Reject(ctx)
}

// Verify implements block.Block
func (b *chainBlockWrapper) Verify(ctx context.Context) error {
	// Forward to embedded chainblock.Block
	return b.Block.Verify(ctx)
}

// ShouldVerifyWithContext implements block.WithVerifyContext
func (b *chainBlockWrapper) ShouldVerifyWithContext(ctx context.Context) (bool, error) {
	// Check if the embedded block implements WithVerifyContext
	if withCtx, ok := b.Block.(chainblock.WithVerifyContext); ok {
		return withCtx.ShouldVerifyWithContext(ctx)
	}
	return false, nil
}

// VerifyWithContext implements block.WithVerifyContext
func (b *chainBlockWrapper) VerifyWithContext(ctx context.Context, blockCtx *chainblock.Context) error {
	// Check if the embedded block implements WithVerifyContext
	if withCtx, ok := b.Block.(chainblock.WithVerifyContext); ok {
		return withCtx.VerifyWithContext(ctx, blockCtx)
	}
	// Fall back to regular Verify if WithVerifyContext is not implemented
	return b.Block.Verify(ctx)
}

// protocolBlockWrapper wraps BlockClient to implement protocol/chainblock.Block
type protocolBlockWrapper struct {
	*BlockClient
}

// Status converts choices.Status to uint8 for protocol/chainblock.Block
func (b *protocolBlockWrapper) Status() uint8 {
	return uint8(b.BlockClient.Status())
}

// componentsBlockWrapper wraps BlockClient to implement components/chainblock.Block
type componentsBlockWrapper struct {
	*BlockClient
}

// Status converts choices.Status to uint8 for components/chainblock.Block
func (b *componentsBlockWrapper) Status() uint8 {
	return uint8(b.BlockClient.Status())
}

// bcLookupWrapper wraps consensus context BCLookup to match ids.AliaserReader
// This handles the case where BCLookup is passed as consensuscontext.BCLookup interface
type bcLookupWrapper struct {
	bc consensuscontext.BCLookup
}

func (b *bcLookupWrapper) Lookup(alias string) (ids.ID, error) {
	if b.bc == nil {
		return ids.Empty, fmt.Errorf("BCLookup is nil")
	}
	return b.bc.Lookup(alias)
}

func (b *bcLookupWrapper) PrimaryAlias(id ids.ID) (string, error) {
	if b.bc == nil {
		return "", fmt.Errorf("BCLookup is nil")
	}
	return b.bc.PrimaryAlias(id)
}

func (b *bcLookupWrapper) Aliases(id ids.ID) ([]string, error) {
	if b.bc == nil {
		return nil, fmt.Errorf("BCLookup is nil")
	}
	// Use the Aliases method if available
	return b.bc.Aliases(id)
}

// validatorStateWrapper wraps ValidatorState to match validators.State
type validatorStateWrapper struct {
	vs ValidatorState
}

func (v *validatorStateWrapper) GetCurrentHeight(ctx context.Context) (uint64, error) {
	return v.vs.GetCurrentHeight()
}

func (v *validatorStateWrapper) GetNetID(ctx context.Context, chainID ids.ID) (ids.ID, error) {
	return v.vs.GetNetID(ctx, chainID)
}

func (v *validatorStateWrapper) GetValidatorSet(ctx context.Context, height uint64, netID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	// Get the raw validator set
	valSet, err := v.vs.GetValidatorSet(height, netID)
	if err != nil {
		return nil, err
	}

	// Convert map[ids.NodeID]uint64 to map[ids.NodeID]*validators.GetValidatorOutput
	result := make(map[ids.NodeID]*validators.GetValidatorOutput, len(valSet))
	for nodeID, weight := range valSet {
		result[nodeID] = &validators.GetValidatorOutput{
			NodeID: nodeID,
			Weight: weight,
		}
	}
	return result, nil
}

func (v *validatorStateWrapper) GetMinimumHeight(ctx context.Context) (uint64, error) {
	// GetMinimumHeight is optional - return 0 if not available
	if vs, ok := v.vs.(interface {
		GetMinimumHeight(context.Context) (uint64, error)
	}); ok {
		return vs.GetMinimumHeight(ctx)
	}
	return 0, nil
}

// GetCurrentValidators implements validators.State
func (v *validatorStateWrapper) GetCurrentValidators(ctx context.Context, height uint64, netID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	// Get validators at specified height
	return v.GetValidatorSet(ctx, height, netID)
}

// ValidatorState interface for wrapping
type ValidatorState interface {
	GetCurrentHeight() (uint64, error)
	GetNetID(context.Context, ids.ID) (ids.ID, error)
	GetValidatorSet(uint64, ids.ID) (map[ids.NodeID]uint64, error)
}
