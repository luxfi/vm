// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package dag provides RPC infrastructure for DAG-based VMs (DAGVM).
// This implements the client for VMs that use vertices with multiple parents.
package dag

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/luxfi/log"
	"github.com/luxfi/metric"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/protobuf/types/known/emptypb"

	consensuscontext "github.com/luxfi/consensus/context"
	"github.com/luxfi/consensus/core/choices"
	validators "github.com/luxfi/consensus/validator"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	platformwarp "github.com/luxfi/protocol/p/warp"
	"github.com/luxfi/protocol/p/warp/gwarp"
	"github.com/luxfi/resource"
	"github.com/luxfi/codec/wrappers"
	"github.com/luxfi/vm/api/metrics"
	"github.com/luxfi/vm/chains/atomic"
	"github.com/luxfi/vm/chains/atomic/gsharedmemory"
	"github.com/luxfi/vm/internal/database/rpcdb"
	"github.com/luxfi/vm/internal/ids/galiasreader"
	"github.com/luxfi/vm/rpc/appsender"
	"github.com/luxfi/vm/rpc/ghttp"
	"github.com/luxfi/vm/rpc/grpcutils"
	"github.com/luxfi/vm/rpc/gvalidators"
	"github.com/luxfi/vm/rpc/runtime"
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
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

var (
	errUnsupportedFXs = errors.New("unsupported feature extensions")

	_ DAGVM           = (*Client)(nil)
	_ metric.Gatherer = (*Client)(nil)
)

// Client is an implementation of a DAGVM that talks over RPC.
// This is the client-side of the RPC DAGVM interface, running in the node process.
type Client struct {
	logger          log.Logger
	client          dagpb.DAGVMClient
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

// NewClient returns a DAGVM Client connected to a remote DAGVM Server.
func NewClient(
	clientConn *grpc.ClientConn,
	runtime runtime.Stopper,
	pid int,
	processTracker resource.ProcessTracker,
	metricsGatherer metrics.MultiGatherer,
	logger log.Logger,
) *Client {
	return &Client{
		client:          dagpb.NewDAGVMClient(clientConn),
		runtime:         runtime,
		pid:             pid,
		processTracker:  processTracker,
		metricsGatherer: metricsGatherer,
		conns:           []*grpc.ClientConn{clientConn},
		logger:          logger,
	}
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
	if cc, ok := chainCtxIface.(*consensuscontext.Context); ok && cc != nil {
		consensusCtx = cc
		ctx = consensuscontext.WithIDs(ctx, consensuscontext.IDs{
			NetworkID: consensusCtx.NetworkID,
			ChainID:   consensusCtx.ChainID,
			NodeID:    consensusCtx.NodeID,
			PublicKey: consensusCtx.PublicKey,
		})
	}

	// Get the current database from the manager
	var db database.Database
	if currentDB, ok := dbIface.(interface{ Current() database.Database }); ok {
		db = currentDB.Current()
	} else if directDB, ok := dbIface.(database.Database); ok {
		db = directDB
	}
	if db == nil {
		return fmt.Errorf("unable to get database from manager: dbIface type is %T", dbIface)
	}
	if len(fxs) != 0 {
		return errUnsupportedFXs
	}

	if consensusCtx == nil {
		return errors.New("consensus context is required for DAG VM initialization")
	}

	var primaryAlias string
	if consensusCtx.BCLookup != nil {
		if bcl, ok := consensusCtx.BCLookup.(ids.AliaserReader); ok {
			var err error
			primaryAlias, err = bcl.PrimaryAlias(consensusCtx.ChainID)
			if err != nil {
				primaryAlias = consensusCtx.ChainID.String()
			}
		} else {
			primaryAlias = consensusCtx.ChainID.String()
		}
	} else {
		primaryAlias = consensusCtx.ChainID.String()
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
	if consensusCtx.Log != nil {
		if logger, ok := consensusCtx.Log.(log.Logger); ok && !logger.IsZero() {
			logger.Info("grpc: serving database",
				log.String("address", dbServerAddr),
			)
		}
	}

	if consensusCtx.SharedMemory != nil {
		if sm, ok := consensusCtx.SharedMemory.(atomic.SharedMemory); ok {
			vm.sharedMemory = gsharedmemory.NewServer(sm, db)
		}
	}
	if consensusCtx.BCLookup != nil {
		if bcl, ok := consensusCtx.BCLookup.(ids.AliaserReader); ok {
			vm.bcLookup = galiasreader.NewServer(bcl)
		}
	}
	if appSender != nil {
		if sender, ok := appSender.(warp.Sender); ok {
			vm.appSender = appsender.NewServer(sender)
		}
	}
	if consensusCtx.ValidatorState != nil {
		if vs, ok := consensusCtx.ValidatorState.(validators.State); ok {
			vm.validatorStateServer = gvalidators.NewServer(vs)
		}
	}
	if consensusCtx.WarpSigner != nil {
		if ws, ok := consensusCtx.WarpSigner.(platformwarp.Signer); ok {
			vm.warpSignerServer = gwarp.NewServer(ws)
		}
	}

	serverListener, err := grpcutils.NewListener()
	if err != nil {
		return err
	}
	serverAddr := serverListener.Addr().String()

	go grpcutils.Serve(serverListener, vm.newInitServer())
	if consensusCtx.Log != nil {
		if logger, ok := consensusCtx.Log.(log.Logger); ok && !logger.IsZero() {
			logger.Info("grpc: serving vm services",
				log.String("address", serverAddr),
			)
		}
	}

	var publicKeyBytes []byte
	if len(consensusCtx.PublicKey) > 0 {
		publicKeyBytes = consensusCtx.PublicKey
	}

	_, err = vm.client.Initialize(ctx, &dagpb.InitializeRequest{
		NetworkId:    consensusCtx.NetworkID,
		ChainId:      consensusCtx.ChainID[:],
		NodeId:       consensusCtx.NodeID.Bytes(),
		PublicKey:    publicKeyBytes,
		XChainId:     consensusCtx.XChainID[:],
		CChainId:     consensusCtx.CChainID[:],
		LuxAssetId:   consensusCtx.XAssetID[:],
		ChainDataDir: consensusCtx.ChainDataDir,
		GenesisBytes: genesisBytes,
		UpgradeBytes: upgradeBytes,
		ConfigBytes:  configBytes,
		DbServerAddr: dbServerAddr,
		ServerAddr:   serverAddr,
	})
	if err != nil {
		return err
	}

	if consensusCtx.Metrics != nil {
		if m, ok := consensusCtx.Metrics.(metrics.MultiGatherer); ok {
			if err := m.Register("vm", vm); err != nil {
				return err
			}
		}
	}

	return nil
}

func (vm *Client) newDBServer(db database.Database) *grpc.Server {
	server := grpcutils.NewServer(
		grpcutils.WithUnaryInterceptor(vm.grpcServerMetrics.UnaryServerInterceptor()),
		grpcutils.WithStreamInterceptor(vm.grpcServerMetrics.StreamServerInterceptor()),
	)

	grpcHealth := health.NewServer()
	grpcHealth.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	vm.serverCloser.Add(server)

	rpcdbpb.RegisterDatabaseServer(server, rpcdb.NewServer(db))
	healthpb.RegisterHealthServer(server, grpcHealth)

	grpc_metric.Register(server)

	return server
}

func (vm *Client) newInitServer() *grpc.Server {
	server := grpcutils.NewServer(
		grpcutils.WithUnaryInterceptor(vm.grpcServerMetrics.UnaryServerInterceptor()),
		grpcutils.WithStreamInterceptor(vm.grpcServerMetrics.StreamServerInterceptor()),
	)

	grpcHealth := health.NewServer()
	grpcHealth.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	vm.serverCloser.Add(server)

	sharedmemorypb.RegisterSharedMemoryServer(server, vm.sharedMemory)
	aliasreaderpb.RegisterAliasReaderServer(server, vm.bcLookup)
	appsenderpb.RegisterAppSenderServer(server, vm.appSender)
	healthpb.RegisterHealthServer(server, grpcHealth)
	validatorstatepb.RegisterValidatorStateServer(server, vm.validatorStateServer)
	warppb.RegisterSignerServer(server, vm.warpSignerServer)

	grpc_metric.Register(server)

	return server
}

func (vm *Client) SetState(ctx context.Context, state uint32) error {
	_, err := vm.client.SetState(ctx, &dagpb.SetStateRequest{
		State: dagpb.State(state),
	})
	return err
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
	// Connected is optional for RPC DAGVM
	return nil
}

func (vm *Client) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	// Disconnected is optional for RPC DAGVM
	return nil
}

func (vm *Client) ParseVertex(ctx context.Context, bytes []byte) (Vertex, error) {
	resp, err := vm.client.ParseVertex(ctx, &dagpb.ParseVertexRequest{
		Bytes: bytes,
	})
	if err != nil {
		return nil, err
	}
	if errEnum := resp.Err; errEnum != dagpb.Error_ERROR_UNSPECIFIED {
		return nil, errEnumToError[errEnum]
	}

	id, err := ids.ToID(resp.Id)
	if err != nil {
		return nil, err
	}

	parentIDs := make([]ids.ID, len(resp.ParentIds))
	for i, parentIDBytes := range resp.ParentIds {
		parentIDs[i], err = ids.ToID(parentIDBytes)
		if err != nil {
			return nil, err
		}
	}

	txIDs := make([]ids.ID, len(resp.TxIds))
	for i, txIDBytes := range resp.TxIds {
		txIDs[i], err = ids.ToID(txIDBytes)
		if err != nil {
			return nil, err
		}
	}

	timestamp, _ := grpcutils.TimestampAsTime(resp.Timestamp)

	return &vertexClient{
		vm:        vm,
		id:        id,
		bytes:     bytes,
		height:    resp.Height,
		epoch:     resp.Epoch,
		parentIDs: parentIDs,
		txIDs:     txIDs,
		timestamp: timestamp,
	}, nil
}

func (vm *Client) BuildVertex(ctx context.Context) (Vertex, error) {
	resp, err := vm.client.BuildVertex(ctx, &dagpb.BuildVertexRequest{})
	if err != nil {
		return nil, err
	}

	id, err := ids.ToID(resp.Id)
	if err != nil {
		return nil, err
	}

	parentIDs := make([]ids.ID, len(resp.ParentIds))
	for i, parentIDBytes := range resp.ParentIds {
		parentIDs[i], err = ids.ToID(parentIDBytes)
		if err != nil {
			return nil, err
		}
	}

	txIDs := make([]ids.ID, len(resp.TxIds))
	for i, txIDBytes := range resp.TxIds {
		txIDs[i], err = ids.ToID(txIDBytes)
		if err != nil {
			return nil, err
		}
	}

	timestamp, _ := grpcutils.TimestampAsTime(resp.Timestamp)

	return &vertexClient{
		vm:        vm,
		id:        id,
		bytes:     resp.Bytes,
		height:    resp.Height,
		epoch:     resp.Epoch,
		parentIDs: parentIDs,
		txIDs:     txIDs,
		timestamp: timestamp,
	}, nil
}

func (vm *Client) GetVertex(ctx context.Context, vtxID ids.ID) (Vertex, error) {
	resp, err := vm.client.GetVertex(ctx, &dagpb.GetVertexRequest{
		Id: vtxID[:],
	})
	if err != nil {
		return nil, err
	}
	if errEnum := resp.Err; errEnum != dagpb.Error_ERROR_UNSPECIFIED {
		return nil, errEnumToError[errEnum]
	}

	parentIDs := make([]ids.ID, len(resp.ParentIds))
	for i, parentIDBytes := range resp.ParentIds {
		parentIDs[i], err = ids.ToID(parentIDBytes)
		if err != nil {
			return nil, err
		}
	}

	txIDs := make([]ids.ID, len(resp.TxIds))
	for i, txIDBytes := range resp.TxIds {
		txIDs[i], err = ids.ToID(txIDBytes)
		if err != nil {
			return nil, err
		}
	}

	timestamp, _ := grpcutils.TimestampAsTime(resp.Timestamp)

	return &vertexClient{
		vm:        vm,
		id:        vtxID,
		bytes:     resp.Bytes,
		height:    resp.Height,
		epoch:     resp.Epoch,
		parentIDs: parentIDs,
		txIDs:     txIDs,
		timestamp: timestamp,
	}, nil
}

func (vm *Client) SetPreference(ctx context.Context, vtxID ids.ID) error {
	_, err := vm.client.SetPreference(ctx, &dagpb.SetPreferenceRequest{
		Id: vtxID[:],
	})
	return err
}

func (vm *Client) LastAccepted(ctx context.Context) (ids.ID, error) {
	resp, err := vm.client.LastAccepted(ctx, &emptypb.Empty{})
	if err != nil {
		return ids.Empty, err
	}
	return ids.ToID(resp.Id)
}

func (vm *Client) HealthCheck(ctx context.Context) (interface{}, error) {
	health, err := vm.client.Health(ctx, &emptypb.Empty{})
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

func (vm *Client) WaitForEvent(ctx context.Context) (interface{}, error) {
	resp, err := vm.client.WaitForEvent(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return resp.Event, nil
}

func (vm *Client) Gather() ([]*metric.MetricFamily, error) {
	resp, err := vm.client.Gather(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return metric.DTOToNative(resp.MetricFamilies), nil
}

// vertexClient is the client-side representation of a vertex received from the server.
type vertexClient struct {
	vm *Client

	id        ids.ID
	bytes     []byte
	height    uint64
	epoch     uint32
	parentIDs []ids.ID
	txIDs     []ids.ID
	timestamp time.Time
	status    choices.Status
}

var _ Vertex = (*vertexClient)(nil)

func (v *vertexClient) ID() ids.ID {
	return v.id
}

func (v *vertexClient) Bytes() []byte {
	return v.bytes
}

func (v *vertexClient) Height() uint64 {
	return v.height
}

func (v *vertexClient) Epoch() uint32 {
	return v.epoch
}

func (v *vertexClient) Parents() []ids.ID {
	return v.parentIDs
}

func (v *vertexClient) Txs() []ids.ID {
	return v.txIDs
}

func (v *vertexClient) Status() choices.Status {
	return v.status
}

func (v *vertexClient) Accept(ctx context.Context) error {
	_, err := v.vm.client.VertexAccept(ctx, &dagpb.VertexAcceptRequest{
		Id: v.id[:],
	})
	if err == nil {
		v.status = choices.Accepted
	}
	return err
}

func (v *vertexClient) Reject(ctx context.Context) error {
	_, err := v.vm.client.VertexReject(ctx, &dagpb.VertexRejectRequest{
		Id: v.id[:],
	})
	if err == nil {
		v.status = choices.Rejected
	}
	return err
}

func (v *vertexClient) Verify(ctx context.Context) error {
	resp, err := v.vm.client.VertexVerify(ctx, &dagpb.VertexVerifyRequest{
		Bytes: v.bytes,
	})
	if err != nil {
		return err
	}
	v.timestamp, _ = grpcutils.TimestampAsTime(resp.Timestamp)
	return nil
}
