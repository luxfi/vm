//go:build grpc

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

	"github.com/luxfi/codec/wrappers"
	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/protocol/p/warp/gwarp"
	"github.com/luxfi/resource"
	apiruntime "github.com/luxfi/runtime"
	"github.com/luxfi/upgrade"
	validators "github.com/luxfi/validators"
	"github.com/luxfi/version"
	"github.com/luxfi/vm/api/metrics"
	vmchain "github.com/luxfi/vm/chain"
	"github.com/luxfi/vm/chains/atomic/gsharedmemory"
	componentschain "github.com/luxfi/vm/components/chain"
	"github.com/luxfi/vm/internal/database/rpcdb"
	"github.com/luxfi/vm/internal/ids/galiasreader"
	senderrpc "github.com/luxfi/vm/rpc/sender"
	"github.com/luxfi/vm/rpc/ghttp"
	"github.com/luxfi/vm/rpc/grpcutils"
	"github.com/luxfi/vm/rpc/gvalidators"
	"github.com/luxfi/vm/rpc/runtime"
	"github.com/luxfi/warp"

	grpc_metric "github.com/grpc-ecosystem/go-grpc-prometheus"
	aliasreaderpb "github.com/luxfi/node/proto/pb/aliasreader"
	senderpb "github.com/luxfi/vm/proto/pb/sender"
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

	_ vmchain.ChainVM                      = (*Client)(nil)
	_ vmchain.BuildBlockWithRuntimeChainVM = (*Client)(nil)
	_ vmchain.BatchedChainVM               = (*Client)(nil)
	_ vmchain.StateSyncableVM              = (*Client)(nil)
	_ metric.Gatherer                      = (*Client)(nil)

	_ vmchain.Block             = (*BlockClient)(nil)
	_ vmchain.WithVerifyRuntime = (*BlockClient)(nil)

	_ vmchain.StateSummary = (*summaryClient)(nil)
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
	*componentschain.State
	logger          log.Logger
	client          vmpb.VMClient
	runtime         runtime.Stopper
	pid             int
	processTracker  resource.ProcessTracker
	metricsGatherer metric.MultiGatherer

	sharedMemory         *gsharedmemory.Server
	bcLookup             *galiasreader.Server
	senderServer         senderrpc.SenderServer
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
	init block.Init,
) error {
	rt := init.Runtime
	if rt == nil {
		return fmt.Errorf("runtime must not be nil")
	}

	// Check fxs is empty
	if len(init.Fx) != 0 {
		return errUnsupportedFXs
	}

	db := init.DB
	genesisBytes := init.Genesis
	upgradeBytes := init.Upgrade
	configBytes := init.Config
	sender := init.Sender

	// Get primary alias for metrics
	var primaryAlias string
	if rt.BCLookup != nil {
		var err error
		primaryAlias, err = rt.BCLookup.PrimaryAlias(rt.ChainID)
		if err != nil {
			primaryAlias = rt.ChainID.String()
		}
	} else {
		primaryAlias = rt.ChainID.String()
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
	if rt.Log != nil {
		rt.Log.Info("grpc: serving database",
			log.String("address", dbServerAddr),
		)
	}

	if rt.SharedMemory != nil {
		vm.sharedMemory = gsharedmemory.NewServer(rt.SharedMemory, db)
	}
	if rt.BCLookup != nil {
		vm.bcLookup = galiasreader.NewServer(rt.BCLookup)
	} else if rt.Log != nil {
		rt.Log.Warn("BCLookup is nil - chain alias resolution will not work for plugin VM")
	}
	if sender != nil {
		vm.senderServer = senderrpc.NewSenderServer(sender)
	}
	if rt.ValidatorState != nil {
		vm.validatorStateServer = gvalidators.NewServer(rt.ValidatorState)
	}
	if rt.WarpSigner != nil {
		vm.warpSignerServer = gwarp.NewServer(rt.WarpSigner)
	}

	serverListener, err := grpcutils.NewListener()
	if err != nil {
		return err
	}
	serverAddr := serverListener.Addr().String()

	go grpcutils.Serve(serverListener, vm.newInitServer())
	if rt.Log != nil {
		rt.Log.Info("grpc: serving vm services",
			log.String("address", serverAddr),
		)
	}

	// Get network upgrades config - type assert if possible, otherwise use defaults
	var upgrades upgrade.Config
	if rt.NetworkUpgrades != nil {
		if u, ok := rt.NetworkUpgrades.(*upgrade.Config); ok && u != nil {
			upgrades = *u
		} else {
			upgrades = upgrade.GetConfig(rt.NetworkID)
		}
	} else {
		upgrades = upgrade.GetConfig(rt.NetworkID)
	}

	networkUpgradesPB := &vmpb.NetworkUpgrades{
		ApricotPhase_1Time:            grpcutils.TimestampFromTime(upgrades.ApricotPhase1Time),
		ApricotPhase_2Time:            grpcutils.TimestampFromTime(upgrades.ApricotPhase2Time),
		ApricotPhase_3Time:            grpcutils.TimestampFromTime(upgrades.ApricotPhase3Time),
		ApricotPhase_4Time:            grpcutils.TimestampFromTime(upgrades.ApricotPhase4Time),
		ApricotPhase_4MinPChainHeight: upgrades.ApricotPhase4MinPChainHeight,
		ApricotPhase_5Time:            grpcutils.TimestampFromTime(upgrades.ApricotPhase5Time),
		ApricotPhasePre_6Time:         grpcutils.TimestampFromTime(upgrades.ApricotPhasePre6Time),
		ApricotPhase_6Time:            grpcutils.TimestampFromTime(upgrades.ApricotPhase6Time),
		ApricotPhasePost_6Time:        grpcutils.TimestampFromTime(upgrades.ApricotPhasePost6Time),
		BanffTime:                     grpcutils.TimestampFromTime(upgrades.BanffTime),
		CortinaTime:                   grpcutils.TimestampFromTime(upgrades.CortinaTime),
		CortinaXChainStopVertexId:     upgrades.CortinaXChainStopVertexID[:],
		DurangoTime:                   grpcutils.TimestampFromTime(upgrades.DurangoTime),
		EtnaTime:                      grpcutils.TimestampFromTime(upgrades.EtnaTime),
		FortunaTime:                   grpcutils.TimestampFromTime(upgrades.FortunaTime),
		GraniteTime:                   grpcutils.TimestampFromTime(upgrades.GraniteTime),
	}

	resp, err := vm.client.Initialize(ctx, &vmpb.InitializeRequest{
		NetworkId:       rt.NetworkID,
		ChainId:         rt.ChainID[:],
		NodeId:          rt.NodeID.Bytes(),
		PublicKey:       rt.PublicKey,
		NetworkUpgrades: networkUpgradesPB,
		XChainId:        rt.XChainID[:],
		CChainId:        rt.CChainID[:],
		LuxAssetId:      rt.XAssetID[:],
		ChainDataDir:    rt.ChainDataDir,
		GenesisBytes:    genesisBytes,
		UpgradeBytes:    upgradeBytes,
		ConfigBytes:     configBytes,
		DbServerAddr:    dbServerAddr,
		ServerAddr:      serverAddr,
	})
	if err != nil {
		return err
	}

	if rt.Metrics != nil {
		// Use "vm" prefix to avoid conflicts with the chain ID prefix already registered
		if err := rt.Metrics.Register("vm", vm); err != nil {
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

	// We don't need to check whether this is a block.WithVerifyRuntime because
	// we'll never Verify this block.
	lastAcceptedBlk := &BlockClient{
		VM:        vm,
		ID_:       id,
		ParentID_: parentID,
		Bytes_:    resp.Bytes,
		Height_:   resp.Height,
		Time_:     time,
	}

	// Initialize the State if not already done
	if vm.State == nil {
		wrappedBlk := &protocolBlockWrapper{BlockClient: lastAcceptedBlk}
		vm.State = componentschain.NewState(&componentschain.Config{
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
	if vm.senderServer != nil {
		if grpcReg := vm.senderServer.GRPCRegistrar(); grpcReg != nil {
			senderpb.RegisterSenderServer(server, grpcReg.(senderpb.SenderServer))
		}
	}
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

	// We don't need to check whether this is a block.WithVerifyRuntime because
	// we'll never Verify this block.
	return vm.SetLastAcceptedBlock(&protocolBlockWrapper{BlockClient: &BlockClient{
		VM:        vm,
		ID_:       id,
		ParentID_: parentID,
		Bytes_:    resp.Bytes,
		Height_:   resp.Height,
		Time_:     time,
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

func (vm *Client) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *version.Application) error {
	// Connected is a no-op for RPC client
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
func (vm *Client) buildBlockWithRuntime(ctx context.Context, blockCtx *apiruntime.Runtime) (vmchain.Block, error) {
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

func (vm *Client) buildBlock(ctx context.Context) (vmchain.Block, error) {
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

func (vm *Client) parseBlock(ctx context.Context, bytes []byte) (vmchain.Block, error) {
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
		ShouldVerifyWithCtx: resp.VerifyWithRuntime,
	}}, nil
}

func (vm *Client) getBlock(ctx context.Context, blkID ids.ID) (vmchain.Block, error) {
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
		ShouldVerifyWithCtx: resp.VerifyWithRuntime,
	}}, nil
}

func (vm *Client) SetPreference(ctx context.Context, blkID ids.ID) error {
	_, err := vm.client.SetPreference(ctx, &vmpb.SetPreferenceRequest{
		Id: blkID[:],
	})
	return err
}

func (vm *Client) HealthCheck(ctx context.Context) (block.HealthCheckResult, error) {
	// HealthCheck is a special case, where we want to fail fast instead of block.
	failFast := grpc.WaitForReady(false)
	health, err := vm.client.Health(ctx, &emptypb.Empty{}, failFast)
	if err != nil {
		return block.HealthCheckResult{}, fmt.Errorf("health check failed: %w", err)
	}

	// Parse details from JSON if available
	var details map[string]string
	if len(health.Details) > 0 {
		_ = json.Unmarshal(health.Details, &details)
	}

	return block.HealthCheckResult{
		Healthy: true,
		Details: details,
	}, nil
}

func (vm *Client) Version(ctx context.Context) (string, error) {
	resp, err := vm.client.Version(ctx, &emptypb.Empty{})
	if err != nil {
		return "", err
	}
	return resp.Version, nil
}

func (vm *Client) Request(ctx context.Context, nodeID ids.NodeID, requestID uint32, deadline time.Time, request []byte) error {
	_, err := vm.client.Request(
		ctx,
		&vmpb.RequestMsg{
			NodeId:    nodeID.Bytes(),
			RequestId: requestID,
			Request:   request,
			Deadline:  grpcutils.TimestampFromTime(deadline),
		},
	)
	return err
}

func (vm *Client) Response(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error {
	_, err := vm.client.Response(
		ctx,
		&vmpb.ResponseMsg{
			NodeId:    nodeID.Bytes(),
			RequestId: requestID,
			Response:  response,
		},
	)
	return err
}

func (vm *Client) RequestFailed(ctx context.Context, nodeID ids.NodeID, requestID uint32, appErr *warp.Error) error {
	msg := &vmpb.RequestFailedMsg{
		NodeId:       nodeID.Bytes(),
		RequestId:    requestID,
		ErrorCode:    appErr.Code,
		ErrorMessage: appErr.Message,
	}

	_, err := vm.client.RequestFailed(ctx, msg)
	return err
}

func (vm *Client) Gossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error {
	_, err := vm.client.Gossip(
		ctx,
		&vmpb.GossipMsg{
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

func (vm *Client) batchedParseBlock(ctx context.Context, blksBytes [][]byte) ([]vmchain.Block, error) {
	resp, err := vm.client.BatchedParseBlock(ctx, &vmpb.BatchedParseBlockRequest{
		Request: blksBytes,
	})
	if err != nil {
		return nil, err
	}
	if len(blksBytes) != len(resp.Response) {
		return nil, errBatchedParseBlockWrongNumberOfBlocks
	}

	res := make([]vmchain.Block, 0, len(blksBytes))
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
			ShouldVerifyWithCtx: blkResp.VerifyWithRuntime,
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
	if err == vmchain.ErrStateSyncableVMNotImplemented {
		return false, nil
	}
	return resp.Enabled, err
}

func (vm *Client) GetOngoingSyncStateSummary(ctx context.Context) (vmchain.StateSummary, error) {
	resp, err := vm.client.GetOngoingSyncStateSummary(ctx, &emptypb.Empty{})
	if err != nil {
		// Check if this is the "not implemented" gRPC error
		if isNotImplementedError(err) {
			return nil, vmchain.ErrStateSyncableVMNotImplemented
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

func (vm *Client) GetLastStateSummary(ctx context.Context) (vmchain.StateSummary, error) {
	resp, err := vm.client.GetLastStateSummary(ctx, &emptypb.Empty{})
	if err != nil {
		// Check if this is the "not implemented" gRPC error
		if isNotImplementedError(err) {
			return nil, vmchain.ErrStateSyncableVMNotImplemented
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

func (vm *Client) ParseStateSummary(ctx context.Context, summaryBytes []byte) (vmchain.StateSummary, error) {
	resp, err := vm.client.ParseStateSummary(
		ctx,
		&vmpb.ParseStateSummaryRequest{
			Bytes: summaryBytes,
		},
	)
	if err != nil {
		// Check if this is the "not implemented" gRPC error
		if isNotImplementedError(err) {
			return nil, vmchain.ErrStateSyncableVMNotImplemented
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

func (vm *Client) GetStateSummary(ctx context.Context, summaryHeight uint64) (vmchain.StateSummary, error) {
	resp, err := vm.client.GetStateSummary(
		ctx,
		&vmpb.GetStateSummaryRequest{
			Height: summaryHeight,
		},
	)
	if err != nil {
		// Check if this is the "not implemented" gRPC error
		if isNotImplementedError(err) {
			return nil, vmchain.ErrStateSyncableVMNotImplemented
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
		ShouldVerifyWithCtx: resp.VerifyWithRuntime,
	}, err
}

// WaitForEvent implements the VM interface by calling the gRPC endpoint on the plugin VM.
// When the VM has pending transactions or state sync completes, it signals via this method.
func (vm *Client) WaitForEvent(ctx context.Context) (block.Message, error) {
	resp, err := vm.client.WaitForEvent(ctx, &emptypb.Empty{})
	if err != nil {
		return block.Message{}, err
	}
	switch resp.Message {
	case vmpb.Message_MESSAGE_BUILD_BLOCK:
		return block.Message{Type: block.PendingTxs}, nil
	case vmpb.Message_MESSAGE_STATE_SYNC_FINISHED:
		return block.Message{Type: block.StateSyncDone}, nil
	default:
		return block.Message{Type: block.PendingTxs}, nil
	}
}

// NewHTTPHandler implements the VM interface
func (vm *Client) NewHTTPHandler(ctx context.Context) (http.Handler, error) {
	// RPC VM uses CreateHandlers instead of a single handler
	return nil, nil
}

// BuildBlock implements the block.ChainVM interface
func (vm *Client) BuildBlock(ctx context.Context) (vmchain.Block, error) {
	innerBlk, err := vm.buildBlock(ctx)
	if err != nil {
		return nil, err
	}
	// Convert vmchain.Block to block.Block through wrapper
	return &chainBlockWrapper{innerBlk}, nil
}

// BuildBlockWithRuntime implements the block.BuildBlockWithRuntimeChainVM interface
func (vm *Client) BuildBlockWithRuntime(ctx context.Context, blockCtx *apiruntime.Runtime) (vmchain.Block, error) {
	innerBlk, err := vm.buildBlockWithRuntime(ctx, blockCtx)
	if err != nil {
		return nil, err
	}
	// Convert vmchain.Block to block.Block through wrapper
	return &chainBlockWrapper{innerBlk}, nil
}

// ParseBlock implements the block.ChainVM interface
func (vm *Client) ParseBlock(ctx context.Context, bytes []byte) (vmchain.Block, error) {
	innerBlk, err := vm.parseBlock(ctx, bytes)
	if err != nil {
		return nil, err
	}
	// Convert vmchain.Block to block.Block through wrapper
	return &chainBlockWrapper{innerBlk}, nil
}

// GetBlock implements the block.ChainVM interface
func (vm *Client) GetBlock(ctx context.Context, id ids.ID) (vmchain.Block, error) {
	innerBlk, err := vm.getBlock(ctx, id)
	if err != nil {
		return nil, err
	}
	// Convert vmchain.Block to block.Block through wrapper
	return &chainBlockWrapper{innerBlk}, nil
}

// LastAccepted implements the block.ChainVM interface
func (vm *Client) LastAccepted(ctx context.Context) (ids.ID, error) {
	lastAcceptedBlk := vm.LastAcceptedBlock()
	return lastAcceptedBlk.ID(), nil
}

// BatchedParseBlock implements the block.BatchedChainVM interface
func (vm *Client) BatchedParseBlock(ctx context.Context, blks [][]byte) ([]vmchain.Block, error) {
	innerBlks, err := vm.batchedParseBlock(ctx, blks)
	if err != nil {
		return nil, err
	}
	// Convert []vmchain.Block to []vmchain.Block
	result := make([]vmchain.Block, len(innerBlks))
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

func (b *BlockClient) ShouldVerifyWithRuntime(context.Context) (bool, error) {
	return b.ShouldVerifyWithCtx, nil
}

func (b *BlockClient) VerifyWithRuntime(ctx context.Context, blockCtx *apiruntime.Runtime) error {
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

func (s *summaryClient) Accept(ctx context.Context) (vmchain.StateSyncMode, error) {
	resp, err := s.vm.client.StateSummaryAccept(
		ctx,
		&vmpb.StateSummaryAcceptRequest{
			Bytes: s.bytes,
		},
	)
	if err != nil {
		return vmchain.StateSyncSkipped, err
	}
	return vmchain.StateSyncMode(resp.Mode), errEnumToError[resp.Err]
}

// chainBlockWrapper wraps a vmchain.Block to implement block.Block
type chainBlockWrapper struct {
	vmchain.Block
}

// Status implements block.Block - returns uint8
func (b *chainBlockWrapper) Status() uint8 {
	// vmchain.Block already has Status() that returns uint8
	return b.Block.Status()
}

// Accept implements block.Block
func (b *chainBlockWrapper) Accept(ctx context.Context) error {
	// Forward to embedded vmchain.Block
	return b.Block.Accept(ctx)
}

// Reject implements block.Block
func (b *chainBlockWrapper) Reject(ctx context.Context) error {
	// Forward to embedded vmchain.Block
	return b.Block.Reject(ctx)
}

// Verify implements block.Block
func (b *chainBlockWrapper) Verify(ctx context.Context) error {
	// Forward to embedded vmchain.Block
	return b.Block.Verify(ctx)
}

// ShouldVerifyWithRuntime implements block.WithVerifyRuntime
func (b *chainBlockWrapper) ShouldVerifyWithRuntime(ctx context.Context) (bool, error) {
	// Check if the embedded block implements WithVerifyRuntime
	if withCtx, ok := b.Block.(vmchain.WithVerifyRuntime); ok {
		return withCtx.ShouldVerifyWithRuntime(ctx)
	}
	return false, nil
}

// VerifyWithRuntime implements block.WithVerifyRuntime
func (b *chainBlockWrapper) VerifyWithRuntime(ctx context.Context, blockCtx *apiruntime.Runtime) error {
	// Check if the embedded block implements WithVerifyRuntime
	if withCtx, ok := b.Block.(vmchain.WithVerifyRuntime); ok {
		return withCtx.VerifyWithRuntime(ctx, blockCtx)
	}
	// Fall back to regular Verify if WithVerifyRuntime is not implemented
	return b.Block.Verify(ctx)
}

// protocolBlockWrapper wraps BlockClient to implement protocol/vmchain.Block
type protocolBlockWrapper struct {
	*BlockClient
}

// Status converts choices.Status to uint8 for protocol/vmchain.Block
func (b *protocolBlockWrapper) Status() uint8 {
	return uint8(b.BlockClient.Status())
}

// componentsBlockWrapper wraps BlockClient to implement components/vmchain.Block
type componentsBlockWrapper struct {
	*BlockClient
}

// Status converts choices.Status to uint8 for components/vmchain.Block
func (b *componentsBlockWrapper) Status() uint8 {
	return uint8(b.BlockClient.Status())
}

// bcLookupWrapper wraps consensus context BCLookup to match ids.AliaserReader
// This handles the case where BCLookup is passed as apiruntime.BCLookup interface
type bcLookupWrapper struct {
	bc apiruntime.BCLookup
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

func (v *validatorStateWrapper) GetChainID(ctx context.Context, chainID ids.ID) (ids.ID, error) {
	return v.vs.GetChainID(ctx, chainID)
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
	GetChainID(context.Context, ids.ID) (ids.ID, error)
	GetValidatorSet(uint64, ids.ID) (map[ids.NodeID]uint64, error)
}
