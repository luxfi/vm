// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package chain provides RPC infrastructure for linear blockchain VMs (ChainVM).
// This implements the server and client for VMs that use blocks with single parents.
package chain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus/collectors"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	consensuscontext "github.com/luxfi/consensus/context"
	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/database"
	"github.com/luxfi/database/corruptabledb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/metric"
	"github.com/luxfi/atomic"
	"github.com/luxfi/codec/wrappers"
	"github.com/luxfi/upgrade"
	"github.com/luxfi/version"
	"github.com/luxfi/vm/api/metrics"
	"github.com/luxfi/vm/chains/atomic/gsharedmemory"
	"github.com/luxfi/vm/internal/database/rpcdb"
	"github.com/luxfi/vm/internal/ids/galiasreader"
	"github.com/luxfi/vm/rpc/appsender"
	"github.com/luxfi/vm/rpc/ghttp"
	"github.com/luxfi/vm/rpc/grpcutils"
	"github.com/luxfi/vm/rpc/gvalidators"
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
)

var (
	_ vmpb.VMServer = (*Server)(nil)
	_ warp.Signer   = (*warpSignerAdapter)(nil)

	errExpectedBlockWithVerifyContext = errors.New("expected block.WithVerifyContext")
	errNilNetworkUpgradesPB           = errors.New("network upgrades protobuf is nil")
)

// Error mappings between protobuf and Go errors
var (
	errEnumToError = map[vmpb.Error]error{
		vmpb.Error_ERROR_CLOSED:                     database.ErrClosed,
		vmpb.Error_ERROR_NOT_FOUND:                  database.ErrNotFound,
		vmpb.Error_ERROR_STATE_SYNC_NOT_IMPLEMENTED: block.ErrRemoteVMNotImplemented,
	}
	errorToErrEnum = map[error]vmpb.Error{
		database.ErrClosed:              vmpb.Error_ERROR_CLOSED,
		database.ErrNotFound:            vmpb.Error_ERROR_NOT_FOUND,
		block.ErrRemoteVMNotImplemented: vmpb.Error_ERROR_STATE_SYNC_NOT_IMPLEMENTED,
	}
)

func errorToRPCError(err error) error {
	if _, ok := errorToErrEnum[err]; ok {
		return nil
	}
	return err
}

// warpSignerAdapter wraps the gRPC warp signer client to implement github.com/luxfi/warp.Signer
// This is needed because plugins (like evm/coreth) expect the warp.Signer from luxfi/warp,
// not from luxfi/platformvm/warp
type warpSignerAdapter struct {
	client warppb.SignerClient
}

func (a *warpSignerAdapter) Sign(msg *warp.UnsignedMessage) ([]byte, error) {
	resp, err := a.client.Sign(context.Background(), &warppb.SignRequest{
		NetworkId:     msg.NetworkID,
		SourceChainId: msg.SourceChainID[:],
		Payload:       msg.Payload,
	})
	if err != nil {
		return nil, err
	}
	return resp.Signature, nil
}

// Server is a ChainVM that is managed over RPC.
// It runs in the plugin process and handles gRPC requests from the node.
type Server struct {
	vmpb.UnsafeVMServer

	vm block.ChainVM
	// If nil, the underlying VM doesn't implement the interface.
	bVM block.BuildBlockWithContextChainVM
	// If nil, the underlying VM doesn't implement the interface.
	ssVM block.StateSyncableVM
	// If nil, the underlying VM doesn't implement the interface.
	appHandler warp.Handler

	allowShutdown *atomic.Atomic[bool]

	metrics metrics.MultiGatherer
	db      database.Database
	log     log.Logger

	serverCloser grpcutils.ServerCloser
	connCloser   wrappers.Closer

	ctx    *consensuscontext.Context
	closed chan struct{}

	// Network information
	networkID uint32
	chainID   ids.ID
	nodeID    ids.NodeID
}

// NewServer returns a ChainVM server instance connected to the provided ChainVM.
// The server runs in the plugin process and handles gRPC requests from the node.
func NewServer(vm block.ChainVM, allowShutdown *atomic.Atomic[bool]) *Server {
	bVM, _ := vm.(block.BuildBlockWithContextChainVM)
	ssVM, _ := vm.(block.StateSyncableVM)
	appHandler, _ := vm.(warp.Handler)
	vmSrv := &Server{
		metrics:       metrics.NewPrefixGatherer(),
		vm:            vm,
		bVM:           bVM,
		ssVM:          ssVM,
		appHandler:    appHandler,
		allowShutdown: allowShutdown,
	}
	return vmSrv
}

func (vm *Server) Initialize(ctx context.Context, req *vmpb.InitializeRequest) (*vmpb.InitializeResponse, error) {
	// NetId from request is no longer used - all chains are on primary network
	// NetworkID (1=mainnet, 2=testnet) is used instead
	chainID, err := ids.ToID(req.ChainId)
	if err != nil {
		return nil, err
	}
	nodeID, err := ids.ToNodeID(req.NodeId)
	if err != nil {
		return nil, err
	}
	var publicKey *bls.PublicKey
	if len(req.PublicKey) > 0 {
		var err error
		publicKey, err = bls.PublicKeyFromCompressedBytes(req.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("couldn't decompress public key: %w", err)
		}
	}

	networkUpgrades, err := convertNetworkUpgrades(req.NetworkUpgrades)
	if err != nil {
		return nil, err
	}

	xChainID, err := ids.ToID(req.XChainId)
	if err != nil {
		return nil, err
	}
	cChainID, err := ids.ToID(req.CChainId)
	if err != nil {
		return nil, err
	}
	luxAssetID, err := ids.ToID(req.LuxAssetId)
	if err != nil {
		return nil, err
	}

	processMetrics, err := metrics.MakeAndRegister(
		vm.metrics,
		"process",
	)
	if err != nil {
		return nil, err
	}

	// Current state of process metrics
	processCollector := collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})
	if err := processMetrics.Register(processCollector); err != nil {
		return nil, err
	}

	// Go process metrics using debug.GCStats
	goCollector := collectors.NewGoCollector()
	if err := processMetrics.Register(goCollector); err != nil {
		return nil, err
	}

	grpcMetrics, err := metrics.MakeAndRegister(
		vm.metrics,
		"grpc",
	)
	if err != nil {
		return nil, err
	}

	// gRPC client metrics
	grpcClientMetrics := grpc_metric.NewClientMetrics()
	if err := grpcMetrics.Register(grpcClientMetrics); err != nil {
		return nil, err
	}

	vmMetrics := metrics.NewPrefixGatherer()
	if err := vm.metrics.Register("vm", vmMetrics); err != nil {
		return nil, err
	}

	// Dial the database
	dbClientConn, err := grpcutils.Dial(
		req.DbServerAddr,
		grpcutils.WithChainUnaryInterceptor(grpcClientMetrics.UnaryClientInterceptor()),
		grpcutils.WithChainStreamInterceptor(grpcClientMetrics.StreamClientInterceptor()),
	)
	if err != nil {
		return nil, err
	}
	vm.connCloser.Add(dbClientConn)

	vm.log = log.NewNoOpLogger() // Use no-op logger to prevent nil panics

	vm.db = corruptabledb.New(
		rpcdb.NewClient(rpcdbpb.NewDatabaseClient(dbClientConn)),
		vm.log,
	)

	clientConn, err := grpcutils.Dial(
		req.ServerAddr,
		grpcutils.WithChainUnaryInterceptor(grpcClientMetrics.UnaryClientInterceptor()),
		grpcutils.WithChainStreamInterceptor(grpcClientMetrics.StreamClientInterceptor()),
	)
	if err != nil {
		// Ignore closing errors to return the original error
		_ = vm.connCloser.Close()
		return nil, err
	}

	vm.connCloser.Add(clientConn)

	sharedMemoryClient := gsharedmemory.NewClient(sharedmemorypb.NewSharedMemoryClient(clientConn))
	bcLookupClient := galiasreader.NewClient(aliasreaderpb.NewAliasReaderClient(clientConn))
	appSenderClient := appsender.NewClient(appsenderpb.NewAppSenderClient(clientConn))
	validatorStateClient := gvalidators.NewClient(validatorstatepb.NewValidatorStateClient(clientConn))
	// Create WarpSigner adapter that implements github.com/luxfi/warp.Signer for plugin compatibility
	warpSignerClient := &warpSignerAdapter{client: warppb.NewSignerClient(clientConn)}

	vm.closed = make(chan struct{})

	// Convert public key to bytes for consensuscontext.Context
	var publicKeyBytes []byte
	if publicKey != nil {
		publicKeyBytes = bls.PublicKeyToCompressedBytes(publicKey)
	}

	vm.ctx = &consensuscontext.Context{
		NetworkID:       req.NetworkId,
		ChainID:         chainID,
		NodeID:          nodeID,
		PublicKey:       publicKeyBytes,
		NetworkUpgrades: networkUpgrades,
		XChainID:        xChainID,
		CChainID:        cChainID,
		XAssetID:        luxAssetID, // Use XAssetID for the primary asset
		Log:             vm.log,
		SharedMemory:    sharedMemoryClient,
		BCLookup:        bcLookupClient,
		Metrics:         vmMetrics,
		ValidatorState:  validatorStateClient,
		ChainDataDir:    req.ChainDataDir,
		WarpSigner:      warpSignerClient,
	}

	// Store network information
	vm.networkID = req.NetworkId
	vm.chainID = chainID
	vm.nodeID = nodeID

	vm.log.Info("initializing VM via gRPC", log.Stringer("chainID", chainID))
	if err := vm.vm.Initialize(ctx, vm.ctx, vm.db, req.GenesisBytes, req.UpgradeBytes, req.ConfigBytes, nil, nil, appSenderClient); err != nil {
		// DEBUG: Write actual error to file since log is no-op
		if f, ferr := os.OpenFile("/tmp/vm-server-init-error.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); ferr == nil {
			fmt.Fprintf(f, "[%s] VM Initialize failed for chain %s: %v\n", time.Now().Format(time.RFC3339), chainID, err)
			f.Close()
		}
		// Ignore errors closing resources to return the original error
		_ = vm.connCloser.Close()
		close(vm.closed)
		vm.log.Error("failed to initialize vm", log.Err(err))
		return nil, err
	}
	vm.log.Info("VM initialized successfully", log.Stringer("chainID", chainID))

	lastAccepted, err := vm.vm.LastAccepted(ctx)
	if err != nil {
		_ = vm.connCloser.Close()
		close(vm.closed)
		vm.log.Error("failed to get last accepted block ID", log.Err(err))
		return nil, err
	}

	blk, err := vm.vm.GetBlock(ctx, lastAccepted)
	if err != nil {
		_ = vm.connCloser.Close()
		close(vm.closed)
		vm.log.Error("failed to get last accepted block", log.Err(err))
		return nil, err
	}
	parentID := blk.Parent()

	// Try to get timestamp if block supports it
	var timestamp *timestamppb.Timestamp
	if timestampable, ok := blk.(interface{ Timestamp() time.Time }); ok {
		timestamp = grpcutils.TimestampFromTime(timestampable.Timestamp())
	}

	return &vmpb.InitializeResponse{
		LastAcceptedId:       lastAccepted[:],
		LastAcceptedParentId: parentID[:],
		Height:               blk.Height(),
		Bytes:                blk.Bytes(),
		Timestamp:            timestamp,
	}, nil
}

func (vm *Server) SetState(ctx context.Context, stateReq *vmpb.SetStateRequest) (*vmpb.SetStateResponse, error) {
	err := vm.vm.SetState(ctx, uint32(stateReq.State))
	if err != nil {
		return nil, err
	}

	lastAccepted, err := vm.vm.LastAccepted(ctx)
	if err != nil {
		return nil, err
	}

	blk, err := vm.vm.GetBlock(ctx, lastAccepted)
	if err != nil {
		return nil, err
	}

	parentID := blk.Parent()
	// Try to get timestamp if block supports it
	var timestamp *timestamppb.Timestamp
	if timestampable, ok := blk.(interface{ Timestamp() time.Time }); ok {
		timestamp = grpcutils.TimestampFromTime(timestampable.Timestamp())
	}

	return &vmpb.SetStateResponse{
		LastAcceptedId:       lastAccepted[:],
		LastAcceptedParentId: parentID[:],
		Height:               blk.Height(),
		Bytes:                blk.Bytes(),
		Timestamp:            timestamp,
	}, nil
}

func (vm *Server) Shutdown(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	vm.allowShutdown.Set(true)
	if vm.closed == nil {
		return &emptypb.Empty{}, nil
	}
	errs := wrappers.Errs{}
	// VM.Shutdown not available in ChainVM interface
	// errs.Add(vm.vm.Shutdown(ctx))
	close(vm.closed)
	vm.serverCloser.Stop()
	errs.Add(vm.connCloser.Close())
	return &emptypb.Empty{}, errs.Err
}

func (vm *Server) CreateHandlers(ctx context.Context, _ *emptypb.Empty) (*vmpb.CreateHandlersResponse, error) {
	type vmWithHandlers interface {
		CreateHandlers(context.Context) (map[string]http.Handler, error)
	}

	handlerVM, ok := vm.vm.(vmWithHandlers)
	if !ok {
		return &vmpb.CreateHandlersResponse{}, nil
	}

	handlers, err := handlerVM.CreateHandlers(ctx)
	if err != nil {
		return nil, err
	}
	resp := &vmpb.CreateHandlersResponse{}
	for prefix, handler := range handlers {
		serverListener, err := grpcutils.NewListener()
		if err != nil {
			return nil, err
		}
		server := grpcutils.NewServer()
		vm.serverCloser.Add(server)
		httppb.RegisterHTTPServer(server, ghttp.NewServer(handler))

		// Start HTTP service
		go grpcutils.Serve(serverListener, server)

		resp.Handlers = append(resp.Handlers, &vmpb.Handler{
			Prefix:     prefix,
			ServerAddr: serverListener.Addr().String(),
		})
	}
	return resp, nil
}

func (vm *Server) NewHTTPHandler(ctx context.Context, _ *emptypb.Empty) (*vmpb.NewHTTPHandlerResponse, error) {
	type vmWithHTTPHandler interface {
		NewHTTPHandler(context.Context) (interface{}, error)
	}

	handlerVM, ok := vm.vm.(vmWithHTTPHandler)
	if !ok {
		return &vmpb.NewHTTPHandlerResponse{}, nil
	}

	handlerIface, err := handlerVM.NewHTTPHandler(ctx)
	if err != nil {
		return nil, err
	}

	if handlerIface == nil {
		return &vmpb.NewHTTPHandlerResponse{}, nil
	}

	handler, ok := handlerIface.(http.Handler)
	if !ok {
		return nil, errors.New("NewHTTPHandler did not return http.Handler")
	}

	serverListener, err := grpcutils.NewListener()
	if err != nil {
		return nil, err
	}
	server := grpcutils.NewServer()
	vm.serverCloser.Add(server)
	httppb.RegisterHTTPServer(server, ghttp.NewServer(handler))

	// Start HTTP service
	go grpcutils.Serve(serverListener, server)

	return &vmpb.NewHTTPHandlerResponse{
		ServerAddr: serverListener.Addr().String(),
	}, nil
}

func (vm *Server) WaitForEvent(ctx context.Context, _ *emptypb.Empty) (*vmpb.WaitForEventResponse, error) {
	message, err := vm.vm.WaitForEvent(ctx)
	if err != nil {
		vm.log.Debug("Received error while waiting for event", "error", err)
	}

	var msgEnum vmpb.Message
	if message != nil {
		if msgVal, ok := message.(int32); ok {
			msgEnum = vmpb.Message(msgVal)
		}
	}

	return &vmpb.WaitForEventResponse{
		Message: msgEnum,
	}, err
}

func (vm *Server) Connected(ctx context.Context, req *vmpb.ConnectedRequest) (*emptypb.Empty, error) {
	_, err := ids.ToNodeID(req.NodeId)
	if err != nil {
		return nil, err
	}

	_ = &version.Application{
		Name:  req.Name,
		Major: int(req.Major),
		Minor: int(req.Minor),
		Patch: int(req.Patch),
	}
	// Connected is not part of block.ChainVM interface
	return &emptypb.Empty{}, nil
}

func (vm *Server) Disconnected(ctx context.Context, req *vmpb.DisconnectedRequest) (*emptypb.Empty, error) {
	_, err := ids.ToNodeID(req.NodeId)
	if err != nil {
		return nil, err
	}
	// Disconnected is not part of block.ChainVM interface
	return &emptypb.Empty{}, nil
}

// If the underlying VM doesn't actually implement this method, its [BuildBlock]
// method will be called instead.
func (vm *Server) BuildBlock(ctx context.Context, req *vmpb.BuildBlockRequest) (*vmpb.BuildBlockResponse, error) {
	var (
		blk block.Block
		err error
	)
	if vm.bVM == nil || req.PChainHeight == nil {
		blk, err = vm.vm.BuildBlock(ctx)
	} else {
		blk, err = vm.bVM.BuildBlockWithContext(ctx, &block.Context{
			PChainHeight: *req.PChainHeight,
		})
	}
	if err != nil {
		return nil, err
	}

	blkWithCtx, verifyWithCtx := blk.(block.WithVerifyContext)
	if verifyWithCtx {
		verifyWithCtx, err = blkWithCtx.ShouldVerifyWithContext(ctx)
		if err != nil {
			return nil, err
		}
	}

	var (
		blkID    = blk.ID()
		parentID = blk.Parent()
	)

	// Try to get timestamp if block supports it
	var timestamp *timestamppb.Timestamp
	if timestampable, ok := blk.(interface{ Timestamp() time.Time }); ok {
		timestamp = grpcutils.TimestampFromTime(timestampable.Timestamp())
	}

	return &vmpb.BuildBlockResponse{
		Id:                blkID[:],
		ParentId:          parentID[:],
		Bytes:             blk.Bytes(),
		Height:            blk.Height(),
		Timestamp:         timestamp,
		VerifyWithContext: verifyWithCtx,
	}, nil
}

func (vm *Server) ParseBlock(ctx context.Context, req *vmpb.ParseBlockRequest) (*vmpb.ParseBlockResponse, error) {
	blk, err := vm.vm.ParseBlock(ctx, req.Bytes)
	if err != nil {
		return nil, err
	}

	blkWithCtx, verifyWithCtx := blk.(block.WithVerifyContext)
	if verifyWithCtx {
		verifyWithCtx, err = blkWithCtx.ShouldVerifyWithContext(ctx)
		if err != nil {
			return nil, err
		}
	}

	var (
		blkID    = blk.ID()
		parentID = blk.Parent()
	)

	// Try to get timestamp if block supports it
	var timestamp *timestamppb.Timestamp
	if timestampable, ok := blk.(interface{ Timestamp() time.Time }); ok {
		timestamp = grpcutils.TimestampFromTime(timestampable.Timestamp())
	}

	return &vmpb.ParseBlockResponse{
		Id:                blkID[:],
		ParentId:          parentID[:],
		Height:            blk.Height(),
		Timestamp:         timestamp,
		VerifyWithContext: verifyWithCtx,
	}, nil
}

func (vm *Server) GetBlock(ctx context.Context, req *vmpb.GetBlockRequest) (*vmpb.GetBlockResponse, error) {
	id, err := ids.ToID(req.Id)
	if err != nil {
		return nil, err
	}
	blk, err := vm.vm.GetBlock(ctx, id)
	if err != nil {
		return &vmpb.GetBlockResponse{
			Err: errorToErrEnum[err],
		}, errorToRPCError(err)
	}

	blkWithCtx, verifyWithCtx := blk.(block.WithVerifyContext)
	if verifyWithCtx {
		verifyWithCtx, err = blkWithCtx.ShouldVerifyWithContext(ctx)
		if err != nil {
			return nil, err
		}
	}

	parentID := blk.Parent()

	// Try to get timestamp if block supports it
	var timestamp *timestamppb.Timestamp
	if timestampable, ok := blk.(interface{ Timestamp() time.Time }); ok {
		timestamp = grpcutils.TimestampFromTime(timestampable.Timestamp())
	}

	return &vmpb.GetBlockResponse{
		ParentId:          parentID[:],
		Bytes:             blk.Bytes(),
		Height:            blk.Height(),
		Timestamp:         timestamp,
		VerifyWithContext: verifyWithCtx,
	}, nil
}

func (vm *Server) SetPreference(ctx context.Context, req *vmpb.SetPreferenceRequest) (*emptypb.Empty, error) {
	id, err := ids.ToID(req.Id)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, vm.vm.SetPreference(ctx, id)
}

func (vm *Server) Health(ctx context.Context, _ *emptypb.Empty) (*vmpb.HealthResponse, error) {
	type vmWithHealthCheck interface {
		HealthCheck(context.Context) (interface{}, error)
	}

	var vmHealth interface{}
	if healthVM, ok := vm.vm.(vmWithHealthCheck); ok {
		var err error
		vmHealth, err = healthVM.HealthCheck(ctx)
		if err != nil {
			return &vmpb.HealthResponse{}, err
		}
	}

	dbHealth, err := vm.db.HealthCheck(ctx)
	if err != nil {
		return &vmpb.HealthResponse{}, err
	}
	report := map[string]interface{}{
		"database": dbHealth,
		"health":   vmHealth,
	}

	details, err := json.Marshal(report)
	return &vmpb.HealthResponse{
		Details: details,
	}, err
}

func (vm *Server) Version(ctx context.Context, _ *emptypb.Empty) (*vmpb.VersionResponse, error) {
	// Version not available in ChainVM interface, check if VM implements it
	type versionGetter interface {
		Version(context.Context) (string, error)
	}

	var version string
	var err error
	if vg, ok := vm.vm.(versionGetter); ok {
		version, err = vg.Version(ctx)
	} else {
		version = "1.0.0" // Default version
	}

	return &vmpb.VersionResponse{
		Version: version,
	}, err
}

func (vm *Server) AppRequest(ctx context.Context, req *vmpb.AppRequestMsg) (*emptypb.Empty, error) {
	nodeID, err := ids.ToNodeID(req.NodeId)
	if err != nil {
		return nil, err
	}
	deadline, err := grpcutils.TimestampAsTime(req.Deadline)
	if err != nil {
		return nil, err
	}
	if vm.appHandler == nil {
		return nil, errors.New("AppRequest not implemented")
	}
	_, appErr := vm.appHandler.Request(ctx, nodeID, req.RequestId, deadline, req.Request)
	if appErr != nil {
		return nil, fmt.Errorf("app error: %d - %s", appErr.Code, appErr.Message)
	}
	return &emptypb.Empty{}, nil
}

func (vm *Server) AppRequestFailed(ctx context.Context, req *vmpb.AppRequestFailedMsg) (*emptypb.Empty, error) {
	nodeID, err := ids.ToNodeID(req.NodeId)
	if err != nil {
		return nil, err
	}

	appErr := &warp.Error{
		Code:    req.ErrorCode,
		Message: req.ErrorMessage,
	}

	type vmWithAppRequestFailed interface {
		AppRequestFailed(context.Context, ids.NodeID, uint32, *warp.Error) error
	}

	if failedVM, ok := vm.vm.(vmWithAppRequestFailed); ok {
		return &emptypb.Empty{}, failedVM.AppRequestFailed(ctx, nodeID, req.RequestId, appErr)
	}

	// AppRequestFailed is optional
	return &emptypb.Empty{}, nil
}

func (vm *Server) AppResponse(ctx context.Context, req *vmpb.AppResponseMsg) (*emptypb.Empty, error) {
	nodeID, err := ids.ToNodeID(req.NodeId)
	if err != nil {
		return nil, err
	}
	if vm.appHandler == nil {
		return nil, errors.New("AppResponse not implemented")
	}
	return &emptypb.Empty{}, vm.appHandler.Response(ctx, nodeID, req.RequestId, req.Response)
}

func (vm *Server) AppGossip(ctx context.Context, req *vmpb.AppGossipMsg) (*emptypb.Empty, error) {
	nodeID, err := ids.ToNodeID(req.NodeId)
	if err != nil {
		return nil, err
	}
	if vm.appHandler == nil {
		return nil, errors.New("AppGossip not implemented")
	}
	return &emptypb.Empty{}, vm.appHandler.Gossip(ctx, nodeID, req.Msg)
}

func (vm *Server) Gather(context.Context, *emptypb.Empty) (*vmpb.GatherResponse, error) {
	metrics, err := vm.metrics.Gather()
	return &vmpb.GatherResponse{MetricFamilies: metric.NativeToDTO(metrics)}, err
}

func (vm *Server) GetAncestors(ctx context.Context, req *vmpb.GetAncestorsRequest) (*vmpb.GetAncestorsResponse, error) {
	blkID, err := ids.ToID(req.BlkId)
	if err != nil {
		return nil, err
	}
	maxBlksNum := int(req.MaxBlocksNum)
	maxBlksSize := int(req.MaxBlocksSize)
	maxBlocksRetrievalTime := time.Duration(req.MaxBlocksRetrivalTime)

	blocks, err := block.GetAncestors(
		ctx,
		vm.vm,
		blkID,
		maxBlksNum,
		maxBlksSize,
		maxBlocksRetrievalTime,
	)
	if err != nil {
		return nil, err
	}
	return &vmpb.GetAncestorsResponse{
		BlksBytes: blocks,
	}, nil
}

func (vm *Server) BatchedParseBlock(
	ctx context.Context,
	req *vmpb.BatchedParseBlockRequest,
) (*vmpb.BatchedParseBlockResponse, error) {
	blocks := make([]*vmpb.ParseBlockResponse, len(req.Request))
	for i, blockBytes := range req.Request {
		block, err := vm.ParseBlock(ctx, &vmpb.ParseBlockRequest{
			Bytes: blockBytes,
		})
		if err != nil {
			return nil, err
		}
		blocks[i] = block
	}
	return &vmpb.BatchedParseBlockResponse{
		Response: blocks,
	}, nil
}

func (vm *Server) GetBlockIDAtHeight(
	ctx context.Context,
	req *vmpb.GetBlockIDAtHeightRequest,
) (*vmpb.GetBlockIDAtHeightResponse, error) {
	blkID, err := vm.vm.GetBlockIDAtHeight(ctx, req.Height)
	return &vmpb.GetBlockIDAtHeightResponse{
		BlkId: blkID[:],
		Err:   errorToErrEnum[err],
	}, errorToRPCError(err)
}

func (vm *Server) StateSyncEnabled(ctx context.Context, _ *emptypb.Empty) (*vmpb.StateSyncEnabledResponse, error) {
	var (
		enabled bool
		err     error
	)
	if vm.ssVM != nil {
		enabled, err = vm.ssVM.StateSyncEnabled(ctx)
	}

	return &vmpb.StateSyncEnabledResponse{
		Enabled: enabled,
		Err:     errorToErrEnum[err],
	}, errorToRPCError(err)
}

func (vm *Server) GetOngoingSyncStateSummary(
	ctx context.Context,
	_ *emptypb.Empty,
) (*vmpb.GetOngoingSyncStateSummaryResponse, error) {
	var (
		summary block.StateSummary
		err     error
	)
	if vm.ssVM != nil {
		summary, err = vm.ssVM.GetOngoingSyncStateSummary(ctx)
	} else {
		err = block.ErrStateSyncableVMNotImplemented
	}

	if err != nil {
		return &vmpb.GetOngoingSyncStateSummaryResponse{
			Err: errorToErrEnum[err],
		}, errorToRPCError(err)
	}

	summaryID := summary.ID()
	return &vmpb.GetOngoingSyncStateSummaryResponse{
		Id:     summaryID[:],
		Height: summary.Height(),
		Bytes:  summary.Bytes(),
	}, nil
}

func (vm *Server) GetLastStateSummary(ctx context.Context, _ *emptypb.Empty) (*vmpb.GetLastStateSummaryResponse, error) {
	var (
		summary block.StateSummary
		err     error
	)
	if vm.ssVM != nil {
		summary, err = vm.ssVM.GetLastStateSummary(ctx)
	} else {
		err = block.ErrStateSyncableVMNotImplemented
	}

	if err != nil {
		return &vmpb.GetLastStateSummaryResponse{
			Err: errorToErrEnum[err],
		}, errorToRPCError(err)
	}

	summaryID := summary.ID()
	return &vmpb.GetLastStateSummaryResponse{
		Id:     summaryID[:],
		Height: summary.Height(),
		Bytes:  summary.Bytes(),
	}, nil
}

func (vm *Server) ParseStateSummary(
	ctx context.Context,
	req *vmpb.ParseStateSummaryRequest,
) (*vmpb.ParseStateSummaryResponse, error) {
	var (
		summary block.StateSummary
		err     error
	)
	if vm.ssVM != nil {
		summary, err = vm.ssVM.ParseStateSummary(ctx, req.Bytes)
	} else {
		err = block.ErrStateSyncableVMNotImplemented
	}

	if err != nil {
		return &vmpb.ParseStateSummaryResponse{
			Err: errorToErrEnum[err],
		}, errorToRPCError(err)
	}

	summaryID := summary.ID()
	return &vmpb.ParseStateSummaryResponse{
		Id:     summaryID[:],
		Height: summary.Height(),
	}, nil
}

func (vm *Server) GetStateSummary(
	ctx context.Context,
	req *vmpb.GetStateSummaryRequest,
) (*vmpb.GetStateSummaryResponse, error) {
	var (
		summary block.StateSummary
		err     error
	)
	if vm.ssVM != nil {
		summary, err = vm.ssVM.GetStateSummary(ctx, req.Height)
	} else {
		err = block.ErrStateSyncableVMNotImplemented
	}

	if err != nil {
		return &vmpb.GetStateSummaryResponse{
			Err: errorToErrEnum[err],
		}, errorToRPCError(err)
	}

	summaryID := summary.ID()
	return &vmpb.GetStateSummaryResponse{
		Id:    summaryID[:],
		Bytes: summary.Bytes(),
	}, nil
}

func (vm *Server) BlockVerify(ctx context.Context, req *vmpb.BlockVerifyRequest) (*vmpb.BlockVerifyResponse, error) {
	blk, err := vm.vm.ParseBlock(ctx, req.Bytes)
	if err != nil {
		return nil, err
	}

	if req.PChainHeight == nil {
		err = blk.Verify(ctx)
	} else {
		blkWithCtx, ok := blk.(block.WithVerifyContext)
		if !ok {
			return nil, fmt.Errorf("%w but got %T", errExpectedBlockWithVerifyContext, blk)
		}
		blockCtx := &block.Context{
			PChainHeight: *req.PChainHeight,
		}
		err = blkWithCtx.VerifyWithContext(ctx, blockCtx)
	}
	if err != nil {
		return nil, err
	}

	// Try to get timestamp if block supports it
	var timestamp *timestamppb.Timestamp
	if timestampable, ok := blk.(interface{ Timestamp() time.Time }); ok {
		timestamp = grpcutils.TimestampFromTime(timestampable.Timestamp())
	}

	return &vmpb.BlockVerifyResponse{
		Timestamp: timestamp,
	}, nil
}

func (vm *Server) BlockAccept(ctx context.Context, req *vmpb.BlockAcceptRequest) (*emptypb.Empty, error) {
	id, err := ids.ToID(req.Id)
	if err != nil {
		return nil, err
	}
	blk, err := vm.vm.GetBlock(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := blk.Accept(ctx); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (vm *Server) BlockReject(ctx context.Context, req *vmpb.BlockRejectRequest) (*emptypb.Empty, error) {
	id, err := ids.ToID(req.Id)
	if err != nil {
		return nil, err
	}
	blk, err := vm.vm.GetBlock(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := blk.Reject(ctx); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (vm *Server) StateSummaryAccept(
	ctx context.Context,
	req *vmpb.StateSummaryAcceptRequest,
) (*vmpb.StateSummaryAcceptResponse, error) {
	var (
		mode = block.StateSyncSkipped
		err  error
	)
	if vm.ssVM != nil {
		var summary block.StateSummary
		summary, err = vm.ssVM.ParseStateSummary(ctx, req.Bytes)
		if err == nil {
			mode, err = summary.Accept(ctx)
		}
	} else {
		err = block.ErrStateSyncableVMNotImplemented
	}

	return &vmpb.StateSummaryAcceptResponse{
		Mode: vmpb.StateSummaryAcceptResponse_Mode(mode),
		Err:  errorToErrEnum[err],
	}, errorToRPCError(err)
}

func convertNetworkUpgrades(pbUpgrades *vmpb.NetworkUpgrades) (upgrade.Config, error) {
	if pbUpgrades == nil {
		return upgrade.Config{}, errNilNetworkUpgradesPB
	}

	ap1, err := grpcutils.TimestampAsTime(pbUpgrades.ApricotPhase_1Time)
	if err != nil {
		return upgrade.Config{}, err
	}
	ap2, err := grpcutils.TimestampAsTime(pbUpgrades.ApricotPhase_2Time)
	if err != nil {
		return upgrade.Config{}, err
	}
	ap3, err := grpcutils.TimestampAsTime(pbUpgrades.ApricotPhase_3Time)
	if err != nil {
		return upgrade.Config{}, err
	}
	ap4, err := grpcutils.TimestampAsTime(pbUpgrades.ApricotPhase_4Time)
	if err != nil {
		return upgrade.Config{}, err
	}
	ap5, err := grpcutils.TimestampAsTime(pbUpgrades.ApricotPhase_5Time)
	if err != nil {
		return upgrade.Config{}, err
	}
	apPre6, err := grpcutils.TimestampAsTime(pbUpgrades.ApricotPhasePre_6Time)
	if err != nil {
		return upgrade.Config{}, err
	}
	ap6, err := grpcutils.TimestampAsTime(pbUpgrades.ApricotPhase_6Time)
	if err != nil {
		return upgrade.Config{}, err
	}
	apPost6, err := grpcutils.TimestampAsTime(pbUpgrades.ApricotPhasePost_6Time)
	if err != nil {
		return upgrade.Config{}, err
	}
	banff, err := grpcutils.TimestampAsTime(pbUpgrades.BanffTime)
	if err != nil {
		return upgrade.Config{}, err
	}
	cortina, err := grpcutils.TimestampAsTime(pbUpgrades.CortinaTime)
	if err != nil {
		return upgrade.Config{}, err
	}
	durango, err := grpcutils.TimestampAsTime(pbUpgrades.DurangoTime)
	if err != nil {
		return upgrade.Config{}, err
	}
	etna, err := grpcutils.TimestampAsTime(pbUpgrades.EtnaTime)
	if err != nil {
		return upgrade.Config{}, err
	}
	fortuna, err := grpcutils.TimestampAsTime(pbUpgrades.FortunaTime)
	if err != nil {
		return upgrade.Config{}, err
	}
	granite, err := grpcutils.TimestampAsTime(pbUpgrades.GraniteTime)
	if err != nil {
		return upgrade.Config{}, err
	}

	cortinaXChainStopVertexID, err := ids.ToID(pbUpgrades.CortinaXChainStopVertexId)
	if err != nil {
		return upgrade.Config{}, err
	}

	return upgrade.Config{
		ApricotPhase1Time:            ap1,
		ApricotPhase2Time:            ap2,
		ApricotPhase3Time:            ap3,
		ApricotPhase4Time:            ap4,
		ApricotPhase4MinPChainHeight: pbUpgrades.ApricotPhase_4MinPChainHeight,
		ApricotPhase5Time:            ap5,
		ApricotPhasePre6Time:         apPre6,
		ApricotPhase6Time:            ap6,
		ApricotPhasePost6Time:        apPost6,
		BanffTime:                    banff,
		CortinaTime:                  cortina,
		CortinaXChainStopVertexID:    cortinaXChainStopVertexID,
		DurangoTime:                  durango,
		EtnaTime:                     etna,
		FortunaTime:                  fortuna,
		GraniteTime:                  granite,
	}, nil
}
