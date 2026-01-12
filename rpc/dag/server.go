// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package dag provides RPC infrastructure for DAG-based VMs (DAGVM).
// This implements the server and client for VMs that use vertices with multiple parents.
package dag

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

	"github.com/luxfi/consensus/runtime"
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/database"
	"github.com/luxfi/database/corruptabledb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/metric"
	"github.com/luxfi/atomic"
	"github.com/luxfi/codec/wrappers"
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
	dagpb "github.com/luxfi/vm/proto/pb/dag"
	httppb "github.com/luxfi/node/proto/pb/http"
	rpcdbpb "github.com/luxfi/node/proto/pb/rpcdb"
	sharedmemorypb "github.com/luxfi/node/proto/pb/sharedmemory"
	validatorstatepb "github.com/luxfi/node/proto/pb/validatorstate"
	warppb "github.com/luxfi/node/proto/pb/warp"
)

var (
	_ dagpb.DAGVMServer = (*Server)(nil)
	_ warp.Signer       = (*warpSignerAdapter)(nil)

	errNilNetworkUpgradesPB = errors.New("network upgrades protobuf is nil")
)

// Error mappings between protobuf and Go errors
var (
	errEnumToError = map[dagpb.Error]error{
		dagpb.Error_ERROR_CLOSED:    database.ErrClosed,
		dagpb.Error_ERROR_NOT_FOUND: database.ErrNotFound,
	}
	errorToErrEnum = map[error]dagpb.Error{
		database.ErrClosed:   dagpb.Error_ERROR_CLOSED,
		database.ErrNotFound: dagpb.Error_ERROR_NOT_FOUND,
	}
)

func errorToRPCError(err error) error {
	if _, ok := errorToErrEnum[err]; ok {
		return nil
	}
	return err
}

// warpSignerAdapter wraps the gRPC warp signer client to implement github.com/luxfi/warp.Signer
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

// Server is a DAGVM that is managed over RPC.
// It runs in the plugin process and handles gRPC requests from the node.
type Server struct {
	dagpb.UnimplementedDAGVMServer

	vm DAGVM
	// If nil, the underlying VM doesn't implement the interface.
	appHandler warp.Handler

	allowShutdown *atomic.Atomic[bool]

	metrics metrics.MultiGatherer
	db      database.Database
	log     log.Logger

	serverCloser grpcutils.ServerCloser
	connCloser   wrappers.Closer

	ctx    *runtime.Runtime
	closed chan struct{}

	// Network information
	networkID uint32
	chainID   ids.ID
	nodeID    ids.NodeID
}

// NewServer returns a DAGVM server instance connected to the provided DAGVM.
// The server runs in the plugin process and handles gRPC requests from the node.
func NewServer(vm DAGVM, allowShutdown *atomic.Atomic[bool]) *Server {
	appHandler, _ := vm.(warp.Handler)
	vmSrv := &Server{
		metrics:       metrics.NewPrefixGatherer(),
		vm:            vm,
		appHandler:    appHandler,
		allowShutdown: allowShutdown,
	}
	return vmSrv
}

func (vm *Server) Initialize(ctx context.Context, req *dagpb.InitializeRequest) (*dagpb.InitializeResponse, error) {
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
		publicKey, err = bls.PublicKeyFromCompressedBytes(req.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("couldn't decompress public key: %w", err)
		}
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

	processCollector := collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})
	if err := processMetrics.Register(processCollector); err != nil {
		return nil, err
	}

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

	vm.log = log.NewNoOpLogger()

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
		_ = vm.connCloser.Close()
		return nil, err
	}

	vm.connCloser.Add(clientConn)

	sharedMemoryClient := gsharedmemory.NewClient(sharedmemorypb.NewSharedMemoryClient(clientConn))
	bcLookupClient := galiasreader.NewClient(aliasreaderpb.NewAliasReaderClient(clientConn))
	appSenderClient := appsender.NewClient(appsenderpb.NewAppSenderClient(clientConn))
	validatorStateClient := gvalidators.NewClient(validatorstatepb.NewValidatorStateClient(clientConn))
	warpSignerClient := &warpSignerAdapter{client: warppb.NewSignerClient(clientConn)}

	vm.closed = make(chan struct{})

	var publicKeyBytes []byte
	if publicKey != nil {
		publicKeyBytes = bls.PublicKeyToCompressedBytes(publicKey)
	}

	vm.ctx = &runtime.Runtime{
		NetworkID:      req.NetworkId,
		ChainID:        chainID,
		NodeID:         nodeID,
		PublicKey:      publicKeyBytes,
		XChainID:       xChainID,
		CChainID:       cChainID,
		XAssetID:       luxAssetID,
		Log:            vm.log,
		SharedMemory:   sharedMemoryClient,
		BCLookup:       bcLookupClient,
		Metrics:        vmMetrics,
		ValidatorState: validatorStateClient,
		ChainDataDir:   req.ChainDataDir,
		WarpSigner:     warpSignerClient,
	}

	vm.networkID = req.NetworkId
	vm.chainID = chainID
	vm.nodeID = nodeID

	vm.log.Info("initializing DAG VM via gRPC", log.Stringer("chainID", chainID))
	if err := vm.vm.Initialize(ctx, vm.ctx, vm.db, req.GenesisBytes, req.UpgradeBytes, req.ConfigBytes, nil, nil, appSenderClient); err != nil {
		if f, ferr := os.OpenFile("/tmp/dag-vm-server-init-error.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); ferr == nil {
			fmt.Fprintf(f, "[%s] DAG VM Initialize failed for chain %s: %v\n", time.Now().Format(time.RFC3339), chainID, err)
			f.Close()
		}
		_ = vm.connCloser.Close()
		close(vm.closed)
		vm.log.Error("failed to initialize dag vm", log.Err(err))
		return nil, err
	}
	vm.log.Info("DAG VM initialized successfully", log.Stringer("chainID", chainID))

	lastAccepted, err := vm.vm.LastAccepted(ctx)
	if err != nil {
		_ = vm.connCloser.Close()
		close(vm.closed)
		vm.log.Error("failed to get last accepted vertex ID", log.Err(err))
		return nil, err
	}

	vtx, err := vm.vm.GetVertex(ctx, lastAccepted)
	if err != nil {
		_ = vm.connCloser.Close()
		close(vm.closed)
		vm.log.Error("failed to get last accepted vertex", log.Err(err))
		return nil, err
	}

	// Get parent IDs (multiple for DAG)
	parentIDs := vtx.Parents()
	parentIDBytes := make([][]byte, len(parentIDs))
	for i, pid := range parentIDs {
		parentIDBytes[i] = pid[:]
	}

	var timestamp *timestamppb.Timestamp
	if timestampable, ok := vtx.(interface{ Timestamp() time.Time }); ok {
		timestamp = grpcutils.TimestampFromTime(timestampable.Timestamp())
	}

	return &dagpb.InitializeResponse{
		LastAcceptedId:        lastAccepted[:],
		LastAcceptedParentIds: parentIDBytes,
		Height:                vtx.Height(),
		Bytes:                 vtx.Bytes(),
		Timestamp:             timestamp,
	}, nil
}

func (vm *Server) SetState(ctx context.Context, stateReq *dagpb.SetStateRequest) (*dagpb.SetStateResponse, error) {
	err := vm.vm.SetState(ctx, uint32(stateReq.State))
	if err != nil {
		return nil, err
	}

	lastAccepted, err := vm.vm.LastAccepted(ctx)
	if err != nil {
		return nil, err
	}

	vtx, err := vm.vm.GetVertex(ctx, lastAccepted)
	if err != nil {
		return nil, err
	}

	parentIDs := vtx.Parents()
	parentIDBytes := make([][]byte, len(parentIDs))
	for i, pid := range parentIDs {
		parentIDBytes[i] = pid[:]
	}

	var timestamp *timestamppb.Timestamp
	if timestampable, ok := vtx.(interface{ Timestamp() time.Time }); ok {
		timestamp = grpcutils.TimestampFromTime(timestampable.Timestamp())
	}

	return &dagpb.SetStateResponse{
		LastAcceptedId:        lastAccepted[:],
		LastAcceptedParentIds: parentIDBytes,
		Height:                vtx.Height(),
		Bytes:                 vtx.Bytes(),
		Timestamp:             timestamp,
	}, nil
}

func (vm *Server) Shutdown(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	vm.allowShutdown.Set(true)
	if vm.closed == nil {
		return &emptypb.Empty{}, nil
	}
	errs := wrappers.Errs{}
	close(vm.closed)
	vm.serverCloser.Stop()
	errs.Add(vm.connCloser.Close())
	return &emptypb.Empty{}, errs.Err
}

func (vm *Server) CreateHandlers(ctx context.Context, _ *emptypb.Empty) (*dagpb.CreateHandlersResponse, error) {
	type vmWithHandlers interface {
		CreateHandlers(context.Context) (map[string]http.Handler, error)
	}

	handlerVM, ok := vm.vm.(vmWithHandlers)
	if !ok {
		return &dagpb.CreateHandlersResponse{}, nil
	}

	handlers, err := handlerVM.CreateHandlers(ctx)
	if err != nil {
		return nil, err
	}
	resp := &dagpb.CreateHandlersResponse{}
	for prefix, handler := range handlers {
		serverListener, err := grpcutils.NewListener()
		if err != nil {
			return nil, err
		}
		server := grpcutils.NewServer()
		vm.serverCloser.Add(server)
		httppb.RegisterHTTPServer(server, ghttp.NewServer(handler))

		go grpcutils.Serve(serverListener, server)

		resp.Handlers = append(resp.Handlers, &dagpb.Handler{
			Prefix:     prefix,
			ServerAddr: serverListener.Addr().String(),
		})
	}
	return resp, nil
}

func (vm *Server) WaitForEvent(ctx context.Context, _ *emptypb.Empty) (*dagpb.WaitForEventResponse, error) {
	message, err := vm.vm.WaitForEvent(ctx)
	if err != nil {
		vm.log.Debug("Received error while waiting for event", "error", err)
	}

	var msgEnum dagpb.Event
	if message != nil {
		if msgVal, ok := message.(int32); ok {
			msgEnum = dagpb.Event(msgVal)
		}
	}

	return &dagpb.WaitForEventResponse{
		Event: msgEnum,
	}, err
}

func (vm *Server) Connected(ctx context.Context, req *dagpb.ConnectedRequest) (*emptypb.Empty, error) {
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
	return &emptypb.Empty{}, nil
}

func (vm *Server) Disconnected(ctx context.Context, req *dagpb.DisconnectedRequest) (*emptypb.Empty, error) {
	_, err := ids.ToNodeID(req.NodeId)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (vm *Server) BuildVertex(ctx context.Context, req *dagpb.BuildVertexRequest) (*dagpb.BuildVertexResponse, error) {
	vtx, err := vm.vm.BuildVertex(ctx)
	if err != nil {
		return nil, err
	}

	vtxID := vtx.ID()
	parentIDs := vtx.Parents()
	parentIDBytes := make([][]byte, len(parentIDs))
	for i, pid := range parentIDs {
		parentIDBytes[i] = pid[:]
	}

	txIDs := vtx.Txs()
	txIDBytes := make([][]byte, len(txIDs))
	for i, txID := range txIDs {
		txIDBytes[i] = txID[:]
	}

	var timestamp *timestamppb.Timestamp
	if timestampable, ok := vtx.(interface{ Timestamp() time.Time }); ok {
		timestamp = grpcutils.TimestampFromTime(timestampable.Timestamp())
	}

	return &dagpb.BuildVertexResponse{
		Id:        vtxID[:],
		ParentIds: parentIDBytes,
		Height:    vtx.Height(),
		Epoch:     vtx.Epoch(),
		Bytes:     vtx.Bytes(),
		TxIds:     txIDBytes,
		Timestamp: timestamp,
	}, nil
}

func (vm *Server) ParseVertex(ctx context.Context, req *dagpb.ParseVertexRequest) (*dagpb.ParseVertexResponse, error) {
	vtx, err := vm.vm.ParseVertex(ctx, req.Bytes)
	if err != nil {
		return &dagpb.ParseVertexResponse{
			Err: errorToErrEnum[err],
		}, errorToRPCError(err)
	}

	vtxID := vtx.ID()
	parentIDs := vtx.Parents()
	parentIDBytes := make([][]byte, len(parentIDs))
	for i, pid := range parentIDs {
		parentIDBytes[i] = pid[:]
	}

	txIDs := vtx.Txs()
	txIDBytes := make([][]byte, len(txIDs))
	for i, txID := range txIDs {
		txIDBytes[i] = txID[:]
	}

	var timestamp *timestamppb.Timestamp
	if timestampable, ok := vtx.(interface{ Timestamp() time.Time }); ok {
		timestamp = grpcutils.TimestampFromTime(timestampable.Timestamp())
	}

	return &dagpb.ParseVertexResponse{
		Id:        vtxID[:],
		ParentIds: parentIDBytes,
		Height:    vtx.Height(),
		Epoch:     vtx.Epoch(),
		TxIds:     txIDBytes,
		Timestamp: timestamp,
	}, nil
}

func (vm *Server) GetVertex(ctx context.Context, req *dagpb.GetVertexRequest) (*dagpb.GetVertexResponse, error) {
	id, err := ids.ToID(req.Id)
	if err != nil {
		return nil, err
	}
	vtx, err := vm.vm.GetVertex(ctx, id)
	if err != nil {
		return &dagpb.GetVertexResponse{
			Err: errorToErrEnum[err],
		}, errorToRPCError(err)
	}

	parentIDs := vtx.Parents()
	parentIDBytes := make([][]byte, len(parentIDs))
	for i, pid := range parentIDs {
		parentIDBytes[i] = pid[:]
	}

	txIDs := vtx.Txs()
	txIDBytes := make([][]byte, len(txIDs))
	for i, txID := range txIDs {
		txIDBytes[i] = txID[:]
	}

	var timestamp *timestamppb.Timestamp
	if timestampable, ok := vtx.(interface{ Timestamp() time.Time }); ok {
		timestamp = grpcutils.TimestampFromTime(timestampable.Timestamp())
	}

	return &dagpb.GetVertexResponse{
		Id:        id[:],
		ParentIds: parentIDBytes,
		Height:    vtx.Height(),
		Epoch:     vtx.Epoch(),
		Bytes:     vtx.Bytes(),
		TxIds:     txIDBytes,
		Timestamp: timestamp,
	}, nil
}

func (vm *Server) SetPreference(ctx context.Context, req *dagpb.SetPreferenceRequest) (*emptypb.Empty, error) {
	id, err := ids.ToID(req.Id)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, vm.vm.SetPreference(ctx, id)
}

func (vm *Server) LastAccepted(ctx context.Context, _ *emptypb.Empty) (*dagpb.LastAcceptedResponse, error) {
	id, err := vm.vm.LastAccepted(ctx)
	if err != nil {
		return nil, err
	}
	return &dagpb.LastAcceptedResponse{
		Id: id[:],
	}, nil
}

func (vm *Server) Health(ctx context.Context, _ *emptypb.Empty) (*dagpb.HealthResponse, error) {
	type vmWithHealthCheck interface {
		HealthCheck(context.Context) (interface{}, error)
	}

	var vmHealth interface{}
	if healthVM, ok := vm.vm.(vmWithHealthCheck); ok {
		var err error
		vmHealth, err = healthVM.HealthCheck(ctx)
		if err != nil {
			return &dagpb.HealthResponse{}, err
		}
	}

	dbHealth, err := vm.db.HealthCheck(ctx)
	if err != nil {
		return &dagpb.HealthResponse{}, err
	}
	report := map[string]interface{}{
		"database": dbHealth,
		"health":   vmHealth,
	}

	details, err := json.Marshal(report)
	return &dagpb.HealthResponse{
		Details: details,
	}, err
}

func (vm *Server) Version(ctx context.Context, _ *emptypb.Empty) (*dagpb.VersionResponse, error) {
	type versionGetter interface {
		Version(context.Context) (string, error)
	}

	var ver string
	var err error
	if vg, ok := vm.vm.(versionGetter); ok {
		ver, err = vg.Version(ctx)
	} else {
		ver = "1.0.0"
	}

	return &dagpb.VersionResponse{
		Version: ver,
	}, err
}

func (vm *Server) AppRequest(ctx context.Context, req *dagpb.AppRequestMsg) (*emptypb.Empty, error) {
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

func (vm *Server) AppRequestFailed(ctx context.Context, req *dagpb.AppRequestFailedMsg) (*emptypb.Empty, error) {
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

	return &emptypb.Empty{}, nil
}

func (vm *Server) AppResponse(ctx context.Context, req *dagpb.AppResponseMsg) (*emptypb.Empty, error) {
	nodeID, err := ids.ToNodeID(req.NodeId)
	if err != nil {
		return nil, err
	}
	if vm.appHandler == nil {
		return nil, errors.New("AppResponse not implemented")
	}
	return &emptypb.Empty{}, vm.appHandler.Response(ctx, nodeID, req.RequestId, req.Response)
}

func (vm *Server) AppGossip(ctx context.Context, req *dagpb.AppGossipMsg) (*emptypb.Empty, error) {
	nodeID, err := ids.ToNodeID(req.NodeId)
	if err != nil {
		return nil, err
	}
	if vm.appHandler == nil {
		return nil, errors.New("AppGossip not implemented")
	}
	return &emptypb.Empty{}, vm.appHandler.Gossip(ctx, nodeID, req.Msg)
}

func (vm *Server) Gather(context.Context, *emptypb.Empty) (*dagpb.GatherResponse, error) {
	mets, err := vm.metrics.Gather()
	return &dagpb.GatherResponse{MetricFamilies: metric.NativeToDTO(mets)}, err
}

func (vm *Server) VertexVerify(ctx context.Context, req *dagpb.VertexVerifyRequest) (*dagpb.VertexVerifyResponse, error) {
	vtx, err := vm.vm.ParseVertex(ctx, req.Bytes)
	if err != nil {
		return nil, err
	}

	if err := vtx.Verify(ctx); err != nil {
		return nil, err
	}

	var timestamp *timestamppb.Timestamp
	if timestampable, ok := vtx.(interface{ Timestamp() time.Time }); ok {
		timestamp = grpcutils.TimestampFromTime(timestampable.Timestamp())
	}

	return &dagpb.VertexVerifyResponse{
		Timestamp: timestamp,
	}, nil
}

func (vm *Server) VertexAccept(ctx context.Context, req *dagpb.VertexAcceptRequest) (*emptypb.Empty, error) {
	id, err := ids.ToID(req.Id)
	if err != nil {
		return nil, err
	}
	vtx, err := vm.vm.GetVertex(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := vtx.Accept(ctx); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (vm *Server) VertexReject(ctx context.Context, req *dagpb.VertexRejectRequest) (*emptypb.Empty, error) {
	id, err := ids.ToID(req.Id)
	if err != nil {
		return nil, err
	}
	vtx, err := vm.vm.GetVertex(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := vtx.Reject(ctx); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
