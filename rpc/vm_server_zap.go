//go:build !grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/database"
	"github.com/luxfi/database/prefixdb"
	"github.com/luxfi/database/zapdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/metric"
	luxruntime "github.com/luxfi/runtime"
	"github.com/luxfi/version"
	"github.com/luxfi/vm/chain"
	"github.com/luxfi/vm/rpc/runtime"
)

// Serve starts the RPC Chain VM server using ZAP transport and performs a
// handshake with the VM runtime service.
//
// The address of the Runtime server is expected to be passed via ENV `runtime.EngineAddressKey`.
// This function connects to the runtime, creates a ZAP listener, sends the handshake,
// and then serves VM requests over ZAP.
func Serve(ctx context.Context, logger log.Logger, vm chain.ChainVM) (retErr error) {
	fmt.Fprintf(os.Stderr, "[ZAP-SERVE] starting Serve\n")

	// Get runtime address from ENV
	runtimeAddr := os.Getenv(runtime.EngineAddressKey)
	if runtimeAddr == "" {
		return fmt.Errorf("required env var missing: %q", runtime.EngineAddressKey)
	}

	// Create ZAP listener with no read timeout (WaitForEvent blocks indefinitely)
	zapCfg := zapwire.DefaultConfig()
	zapCfg.ReadTimeout = 0

	listener, err := zapwire.Listen("127.0.0.1:0", zapCfg)
	if err != nil {
		return fmt.Errorf("failed to create ZAP listener: %w", err)
	}
	vmAddr := listener.Addr().String()
	fmt.Fprintf(os.Stderr, "[ZAP-SERVE] listening on %s\n", vmAddr)

	// Connect to runtime for handshake
	runtimeConn, err := net.Dial("tcp", runtimeAddr)
	if err != nil {
		listener.Close()
		return fmt.Errorf("failed to connect to runtime: %w", err)
	}

	// Send handshake: [4-byte len][4-byte protocol version][vm addr string]
	addrBytes := []byte(vmAddr)
	msgLen := 4 + len(addrBytes) // protocol version + address
	header := make([]byte, 8+len(addrBytes))
	binary.BigEndian.PutUint32(header[:4], uint32(msgLen))
	binary.BigEndian.PutUint32(header[4:8], uint32(version.RPCChainVMProtocol))
	copy(header[8:], addrBytes)

	if _, err := runtimeConn.Write(header); err != nil {
		runtimeConn.Close()
		listener.Close()
		return fmt.Errorf("failed to send handshake: %w", err)
	}

	// Wait for ACK: [1-byte OK]
	ack := make([]byte, 1)
	if _, err := runtimeConn.Read(ack); err != nil {
		runtimeConn.Close()
		listener.Close()
		return fmt.Errorf("failed to read handshake ack: %w", err)
	}
	if ack[0] != 1 {
		runtimeConn.Close()
		listener.Close()
		return fmt.Errorf("handshake failed: ack=%d", ack[0])
	}
	runtimeConn.Close()
	fmt.Fprintf(os.Stderr, "[ZAP-SERVE] handshake complete, starting ZAP server\n")

	// Create ZAP server for VM operations
	server := newZAPVMServer(vm, logger)
	zapServer := zapwire.NewServer(listener, server)

	// Serve requests (blocks until closed)
	err = zapServer.Serve(ctx)
	fmt.Fprintf(os.Stderr, "[ZAP-SERVE] Serve returned: %v\n", err)
	return err
}

// quasarExporter is the OPTIONAL VM-side surface behind zapwire.CapQuasarExport.
// A concrete ChainVM (the C-Chain EVM) implements it to track a Quasar
// (⅔-by-stake) EXPORT-FINAL height distinct from its reorgable local accept tip.
// It is NOT part of the generic chain.ChainVM contract: the plugin server PROBES
// the wrapped VM for it once at construction and, when present, advertises
// CapQuasarExport at the Initialize handshake AND serves the MsgSetQuasarFinalized
// / MsgQuasarHeight round-trips. The method set mirrors the node-side client
// (github.com/luxfi/node/vms/rpcchainvm/zap.Client) so the two ends compose
// across the ZAP boundary. Absent it, the node keeps this chain Nova-only.
type quasarExporter interface {
	// SetLastQuasarFinalized records that the block at height reached ⅔-stake
	// EXPORT finality (drives the VM's finalized/safe tags + warp export gate).
	SetLastQuasarFinalized(height uint64)
	// LastQuasarHeight returns the VM's accept-tip-clamped EXPORT-FINAL height
	// (0 before the first export forms).
	LastQuasarHeight() uint64
}

// zapVMServer implements zapwire.Handler for a VM
type zapVMServer struct {
	vm            chain.ChainVM
	logger        log.Logger
	allowShutdown *bool
	db            database.Database // persistent database, closed on shutdown

	// quasarVM is the wrapped VM viewed through the OPTIONAL quasarExporter
	// surface, or nil if the VM does not implement it. Resolved ONCE by probing vm
	// at construction (a VM's method set is fixed for its life), then read by
	// capabilities() and the two Quasar handlers. nil ⇒ the server never sets
	// CapQuasarExport and refuses the Quasar messages, so the node stays Nova-only.
	quasarVM quasarExporter

	// pendingBlock caches the last built block to prevent rebuilding
	// with a new timestamp while consensus is voting on it.
	// Cleared on BlockAccept or BlockReject.
	pendingBlock     chain.Block
	pendingBlockLock sync.Mutex
}

// NewZAPHandler builds the ZAP-wire server side for a VM.
//
// This is the ONLY way to stand up a real rpc server from outside the package:
// newZAPVMServer is unexported, so without this a consumer can test its client
// against a mock but never against the actual server. It existed through v1.2.7,
// was dropped somewhere in the 1.3 line, and luxfi/node still calls it --
// vms/rpcchainvm/zap/client_quasar_test.go:102 -- so that package failed to
// build outright:
//
//	undefined: rpc.NewZAPHandler
func NewZAPHandler(vm chain.ChainVM, logger log.Logger) zapwire.Handler {
	return newZAPVMServer(vm, logger)
}

func newZAPVMServer(vm chain.ChainVM, logger log.Logger) *zapVMServer {
	allowShutdown := false
	s := &zapVMServer{
		vm:            vm,
		logger:        logger,
		allowShutdown: &allowShutdown,
	}
	// Probe the wrapped VM ONCE for the OPTIONAL Quasar export surface. A hit here
	// is what turns CapQuasarExport from dead-on-arrival into a real capability: the
	// bit is advertised at Initialize and the two Quasar handlers dispatch to this
	// VM. A miss leaves quasarVM nil → generic VM, no export surface.
	if qvm, ok := vm.(quasarExporter); ok {
		s.quasarVM = qvm
	}
	return s
}

// capabilities returns the OPTIONAL cross-boundary add-on bitfield this server
// advertises in InitializeResponse.Capabilities, derived from the one-time probe
// of the wrapped VM. A generic VM implements no add-ons → 0 → the node stays on
// the generic path. This is the SINGLE source of the advertised bitfield; every
// bit set here MUST have a matching handler wired in Handle.
func (s *zapVMServer) capabilities() uint64 {
	var caps uint64
	if s.quasarVM != nil {
		caps |= zapwire.CapQuasarExport
	}
	return caps
}

// Handle implements zapwire.Handler
func (s *zapVMServer) Handle(ctx context.Context, msgType zapwire.MessageType, payload []byte) (retType zapwire.MessageType, retPayload []byte, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("panic in ZAP handler", "msgType", msgType, "panic", r)
			retType = msgType
			retPayload = nil
			retErr = fmt.Errorf("panic in handler: %v", r)
		}
	}()
	switch msgType {
	case zapwire.MsgInitialize:
		return s.handleInitialize(ctx, payload)
	case zapwire.MsgShutdown:
		*s.allowShutdown = true
		return s.handleShutdown(ctx)
	case zapwire.MsgSetState:
		return s.handleSetState(ctx, payload)
	case zapwire.MsgVersion:
		return s.handleVersion(ctx)
	case zapwire.MsgCreateHandlers:
		return s.handleCreateHandlers(ctx)
	case zapwire.MsgBuildBlock:
		return s.handleBuildBlock(ctx)
	case zapwire.MsgParseBlock:
		return s.handleParseBlock(ctx, payload)
	case zapwire.MsgGetBlock:
		return s.handleGetBlock(ctx, payload)
	case zapwire.MsgSetPreference:
		return s.handleSetPreference(ctx, payload)
	case zapwire.MsgBlockVerify:
		return s.handleBlockVerify(ctx, payload)
	case zapwire.MsgBlockAccept:
		return s.handleBlockAccept(ctx, payload)
	case zapwire.MsgBlockReject:
		return s.handleBlockReject(ctx, payload)
	case zapwire.MsgHealth:
		return s.handleHealth(ctx)
	case zapwire.MsgWaitForEvent:
		return s.handleWaitForEvent(ctx)
	case zapwire.MsgBatchedParseBlock:
		return s.handleBatchedParseBlock(ctx, payload)
	case zapwire.MsgGetAncestors:
		return s.handleGetAncestors(ctx, payload)
	case zapwire.MsgConnected:
		return s.handleConnected(ctx, payload)
	case zapwire.MsgDisconnected:
		return s.handleDisconnected(ctx, payload)
	case zapwire.MsgGetBlockIDAtHeight:
		return s.handleGetBlockIDAtHeight(ctx, payload)
	case zapwire.MsgNewHTTPHandler:
		return s.handleNewHTTPHandler(ctx)
	case zapwire.MsgSetQuasarFinalized:
		return s.handleSetQuasarFinalized(ctx, payload)
	case zapwire.MsgQuasarHeight:
		return s.handleQuasarHeight(ctx)
	default:
		s.logger.Warn("unknown ZAP message type", "msgType", msgType)
		return msgType, nil, nil
	}
}

func (s *zapVMServer) handleInitialize(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.InitializeRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgInitialize, nil, fmt.Errorf("decode initialize request: %w", err)
	}

	s.logger.Info("ZAP handleInitialize",
		"networkID", req.NetworkID,
		"chainDataDir", req.ChainDataDir,
		"genesisLen", len(req.GenesisBytes),
	)

	// Decode fixed-length identifiers through the validating constructors;
	// ids.ToID/ToNodeID reject a wire field whose length isn't exactly the ID
	// size, instead of copy() silently zero-padding or truncating it into a
	// different ID.
	chainID, err := ids.ToID(req.ChainID)
	if err != nil {
		return zapwire.MsgInitialize, nil, fmt.Errorf("initialize chainID: %w", err)
	}
	xChainID, err := ids.ToID(req.XChainID)
	if err != nil {
		return zapwire.MsgInitialize, nil, fmt.Errorf("initialize xChainID: %w", err)
	}
	cChainID, err := ids.ToID(req.CChainID)
	if err != nil {
		return zapwire.MsgInitialize, nil, fmt.Errorf("initialize cChainID: %w", err)
	}
	utxoAssetID, err := ids.ToID(req.UTXOAssetID)
	if err != nil {
		return zapwire.MsgInitialize, nil, fmt.Errorf("initialize utxoAssetID: %w", err)
	}
	nodeIDTyped, err := ids.ToNodeID(req.NodeID)
	if err != nil {
		return zapwire.MsgInitialize, nil, fmt.Errorf("initialize nodeID: %w", err)
	}

	// Build runtime with all configuration
	rt := &luxruntime.Runtime{
		NetworkID:    req.NetworkID,
		ChainID:      chainID,
		NodeID:       nodeIDTyped,
		PublicKey:    req.PublicKey,
		XChainID:     xChainID,
		CChainID:     cChainID,
		UTXOAssetID:  utxoAssetID,
		ChainDataDir: req.ChainDataDir,
		Log:          s.logger,
		Metrics:      metric.NewMultiGatherer(),
	}

	// Open persistent database at ChainDataDir for the VM.
	// The database is opened directly by the plugin process since
	// ZAP transport cannot proxy database access across processes.
	dbPath := filepath.Join(req.ChainDataDir, "db")
	baseDB, err := zapdb.New(dbPath, nil, "vm", metric.NewRegistry())
	if err != nil {
		return zapwire.MsgInitialize, nil, fmt.Errorf("open database at %s: %w", dbPath, err)
	}
	s.db = baseDB
	// Use a prefix to avoid collisions with any other data in the same dir
	db := prefixdb.New([]byte("vm"), baseDB)

	// Build the block.Init struct for VM initialization
	init := block.Init{
		Runtime: rt,
		DB:      db,
		Genesis: req.GenesisBytes,
		Upgrade: req.UpgradeBytes,
		Config:  req.ConfigBytes,
	}

	if err := s.vm.Initialize(ctx, init); err != nil {
		return zapwire.MsgInitialize, nil, fmt.Errorf("vm initialize: %w", err)
	}

	// Now get the last accepted block
	lastAccepted, err := s.vm.LastAccepted(ctx)
	if err != nil {
		return zapwire.MsgInitialize, nil, fmt.Errorf("get last accepted: %w", err)
	}

	// Get the last accepted block details for the response
	lastBlock, err := s.vm.GetBlock(ctx, lastAccepted)
	if err != nil {
		return zapwire.MsgInitialize, nil, fmt.Errorf("get last accepted block: %w", err)
	}

	parentID := lastBlock.Parent()
	resp := &zapwire.InitializeResponse{
		LastAcceptedID:       lastAccepted[:],
		LastAcceptedParentID: parentID[:],
		Height:               lastBlock.Height(),
		Bytes:                lastBlock.Bytes(),
		Timestamp:            lastBlock.Timestamp().UnixNano(),
		// Capabilities is probed from the wrapped VM (0 for a generic VM). The
		// node reads it once here to decide which OPTIONAL add-ons to wire.
		Capabilities: s.capabilities(),
	}

	buf := zapwire.GetBuffer()
	resp.Encode(buf)
	result := make([]byte, len(buf.Bytes()))
	copy(result, buf.Bytes())
	zapwire.PutBuffer(buf)

	s.logger.Info("ZAP VM initialized successfully",
		"lastAcceptedID", lastAccepted,
		"height", lastBlock.Height(),
		"quasarExport", s.quasarVM != nil,
	)

	return zapwire.MsgInitialize, result, nil
}

// zapLogger adapts log.Logger to luxruntime.Logger interface
type zapLogger struct {
	logger log.Logger
}

func (l *zapLogger) Debug(msg string, fields ...interface{}) { l.logger.Debug(msg, fields...) }
func (l *zapLogger) Info(msg string, fields ...interface{})  { l.logger.Info(msg, fields...) }
func (l *zapLogger) Warn(msg string, fields ...interface{})  { l.logger.Warn(msg, fields...) }
func (l *zapLogger) Error(msg string, fields ...interface{}) { l.logger.Error(msg, fields...) }
func (l *zapLogger) Fatal(msg string, fields ...interface{}) { l.logger.Error(msg, fields...) }
func (l *zapLogger) IsZero() bool                            { return l.logger == nil }

func (s *zapVMServer) handleShutdown(ctx context.Context) (zapwire.MessageType, []byte, error) {
	err := s.vm.Shutdown(ctx)
	// Close the persistent database after the VM shuts down
	if s.db != nil {
		if dbErr := s.db.Close(); dbErr != nil {
			s.logger.Warn("failed to close database on shutdown", "error", dbErr)
		}
	}
	return zapwire.MsgShutdown, nil, err
}

func (s *zapVMServer) handleSetState(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.SetStateRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgSetState, nil, err
	}

	err := s.vm.SetState(ctx, uint32(req.State))
	return zapwire.MsgSetState, nil, err
}

func (s *zapVMServer) handleVersion(ctx context.Context) (zapwire.MessageType, []byte, error) {
	ver, err := s.vm.Version(ctx)
	if err != nil {
		return zapwire.MsgVersion, nil, err
	}

	resp := &zapwire.VersionResponse{
		Version: ver,
	}

	buf := zapwire.GetBuffer()
	resp.Encode(buf)
	result := make([]byte, len(buf.Bytes()))
	copy(result, buf.Bytes())
	zapwire.PutBuffer(buf)

	return zapwire.MsgVersion, result, nil
}

func (s *zapVMServer) handleCreateHandlers(ctx context.Context) (zapwire.MessageType, []byte, error) {
	// Check if VM implements CreateHandlers
	type vmWithHandlers interface {
		CreateHandlers(context.Context) (map[string]http.Handler, error)
	}

	handlerVM, ok := s.vm.(vmWithHandlers)
	if !ok {
		resp := &zapwire.CreateHandlersResponse{
			Handlers: []zapwire.HTTPHandler{},
		}
		buf := zapwire.GetBuffer()
		resp.Encode(buf)
		result := make([]byte, len(buf.Bytes()))
		copy(result, buf.Bytes())
		zapwire.PutBuffer(buf)
		return zapwire.MsgCreateHandlers, result, nil
	}

	handlers, err := handlerVM.CreateHandlers(ctx)
	if err != nil {
		return zapwire.MsgCreateHandlers, nil, err
	}

	resp := &zapwire.CreateHandlersResponse{
		Handlers: make([]zapwire.HTTPHandler, 0, len(handlers)),
	}

	for prefix, handler := range handlers {
		// Create HTTP listener on a random port
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return zapwire.MsgCreateHandlers, nil, err
		}

		serverAddr := listener.Addr().String()

		// Start HTTP server in background
		server := &http.Server{Handler: handler}
		go func() {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				s.logger.Error("HTTP server error", "prefix", prefix, "error", err)
			}
		}()

		resp.Handlers = append(resp.Handlers, zapwire.HTTPHandler{
			Prefix:     prefix,
			ServerAddr: serverAddr,
		})
	}

	buf := zapwire.GetBuffer()
	resp.Encode(buf)
	result := make([]byte, len(buf.Bytes()))
	copy(result, buf.Bytes())
	zapwire.PutBuffer(buf)

	return zapwire.MsgCreateHandlers, result, nil
}

func (s *zapVMServer) handleBuildBlock(ctx context.Context) (zapwire.MessageType, []byte, error) {
	s.pendingBlockLock.Lock()
	defer s.pendingBlockLock.Unlock()

	// Return cached block if one is already pending consensus vote.
	// This prevents rebuilding with a new timestamp which would change
	// the block ID and invalidate in-flight votes.
	if s.pendingBlock != nil {
		blk := s.pendingBlock
		blkID := blk.ID()
		parentID := blk.Parent()
		resp := &zapwire.BlockResponse{
			ID:        blkID[:],
			ParentID:  parentID[:],
			Bytes:     blk.Bytes(),
			Height:    blk.Height(),
			Timestamp: blk.Timestamp().UnixNano(),
			Err:       zapwire.ErrorUnspecified,
		}
		buf := zapwire.GetBuffer()
		resp.Encode(buf)
		result := make([]byte, len(buf.Bytes()))
		copy(result, buf.Bytes())
		zapwire.PutBuffer(buf)
		return zapwire.MsgBuildBlock, result, nil
	}

	blk, err := s.vm.BuildBlock(ctx)
	if err != nil {
		resp := &zapwire.BlockResponse{
			Err: errorToZAP(err),
		}
		buf := zapwire.GetBuffer()
		resp.Encode(buf)
		result := make([]byte, len(buf.Bytes()))
		copy(result, buf.Bytes())
		zapwire.PutBuffer(buf)
		return zapwire.MsgBuildBlock, result, nil
	}

	// Cache the block so subsequent calls return the same block ID.
	s.pendingBlock = blk

	blkID := blk.ID()
	parentID := blk.Parent()
	resp := &zapwire.BlockResponse{
		ID:        blkID[:],
		ParentID:  parentID[:],
		Bytes:     blk.Bytes(),
		Height:    blk.Height(),
		Timestamp: blk.Timestamp().UnixNano(),
		Err:       zapwire.ErrorUnspecified,
	}

	buf := zapwire.GetBuffer()
	resp.Encode(buf)
	result := make([]byte, len(buf.Bytes()))
	copy(result, buf.Bytes())
	zapwire.PutBuffer(buf)

	return zapwire.MsgBuildBlock, result, nil
}

func (s *zapVMServer) handleParseBlock(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.ParseBlockRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgParseBlock, nil, err
	}

	blk, err := s.vm.ParseBlock(ctx, req.Bytes)
	if err != nil {
		resp := &zapwire.BlockResponse{
			Err: errorToZAP(err),
		}
		buf := zapwire.GetBuffer()
		resp.Encode(buf)
		result := make([]byte, len(buf.Bytes()))
		copy(result, buf.Bytes())
		zapwire.PutBuffer(buf)
		return zapwire.MsgParseBlock, result, nil
	}

	blkID := blk.ID()
	parentID := blk.Parent()
	resp := &zapwire.BlockResponse{
		ID:        blkID[:],
		ParentID:  parentID[:],
		Bytes:     blk.Bytes(),
		Height:    blk.Height(),
		Timestamp: blk.Timestamp().UnixNano(),
		Err:       zapwire.ErrorUnspecified,
	}

	buf := zapwire.GetBuffer()
	resp.Encode(buf)
	result := make([]byte, len(buf.Bytes()))
	copy(result, buf.Bytes())
	zapwire.PutBuffer(buf)

	return zapwire.MsgParseBlock, result, nil
}

func (s *zapVMServer) handleGetBlock(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.GetBlockRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgGetBlock, nil, err
	}

	blkID, err := ids.ToID(req.ID)
	if err != nil {
		return zapwire.MsgGetBlock, nil, err
	}

	blk, err := s.vm.GetBlock(ctx, blkID)
	if err != nil {
		resp := &zapwire.BlockResponse{
			Err: errorToZAP(err),
		}
		buf := zapwire.GetBuffer()
		resp.Encode(buf)
		result := make([]byte, len(buf.Bytes()))
		copy(result, buf.Bytes())
		zapwire.PutBuffer(buf)
		return zapwire.MsgGetBlock, result, nil
	}

	retrievedBlkID := blk.ID()
	parentID := blk.Parent()
	resp := &zapwire.BlockResponse{
		ID:        retrievedBlkID[:],
		ParentID:  parentID[:],
		Bytes:     blk.Bytes(),
		Height:    blk.Height(),
		Timestamp: blk.Timestamp().UnixNano(),
		Err:       zapwire.ErrorUnspecified,
	}

	buf := zapwire.GetBuffer()
	resp.Encode(buf)
	result := make([]byte, len(buf.Bytes()))
	copy(result, buf.Bytes())
	zapwire.PutBuffer(buf)

	return zapwire.MsgGetBlock, result, nil
}

func (s *zapVMServer) handleSetPreference(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.SetPreferenceRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgSetPreference, nil, err
	}

	blkID, err := ids.ToID(req.ID)
	if err != nil {
		return zapwire.MsgSetPreference, nil, err
	}

	err = s.vm.SetPreference(ctx, blkID)
	return zapwire.MsgSetPreference, nil, err
}

func (s *zapVMServer) handleBlockVerify(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.BlockVerifyRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgBlockVerify, nil, err
	}

	blk, err := s.vm.ParseBlock(ctx, req.Bytes)
	if err != nil {
		return zapwire.MsgBlockVerify, nil, err
	}

	err = blk.Verify(ctx)
	return zapwire.MsgBlockVerify, nil, err
}

func (s *zapVMServer) handleBlockAccept(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.BlockAcceptRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgBlockAccept, nil, err
	}

	blkID, err := ids.ToID(req.ID)
	if err != nil {
		return zapwire.MsgBlockAccept, nil, err
	}

	blk, err := s.vm.GetBlock(ctx, blkID)
	if err != nil {
		return zapwire.MsgBlockAccept, nil, err
	}

	err = blk.Accept(ctx)

	// Clear pending block cache so the next BuildBlock creates a fresh block.
	s.pendingBlockLock.Lock()
	s.pendingBlock = nil
	s.pendingBlockLock.Unlock()

	return zapwire.MsgBlockAccept, nil, err
}

func (s *zapVMServer) handleBlockReject(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.BlockRejectRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgBlockReject, nil, err
	}

	blkID, err := ids.ToID(req.ID)
	if err != nil {
		return zapwire.MsgBlockReject, nil, err
	}

	blk, err := s.vm.GetBlock(ctx, blkID)
	if err != nil {
		return zapwire.MsgBlockReject, nil, err
	}

	err = blk.Reject(ctx)

	// Clear pending block cache so the next BuildBlock creates a fresh block.
	s.pendingBlockLock.Lock()
	s.pendingBlock = nil
	s.pendingBlockLock.Unlock()

	return zapwire.MsgBlockReject, nil, err
}

func (s *zapVMServer) handleHealth(ctx context.Context) (zapwire.MessageType, []byte, error) {
	resp := &zapwire.HealthResponse{
		Details: []byte(`{"healthy":true}`),
	}

	buf := zapwire.GetBuffer()
	resp.Encode(buf)
	result := make([]byte, len(buf.Bytes()))
	copy(result, buf.Bytes())
	zapwire.PutBuffer(buf)

	return zapwire.MsgHealth, result, nil
}

func (s *zapVMServer) handleWaitForEvent(ctx context.Context) (zapwire.MessageType, []byte, error) {
	type waitForEventer interface {
		WaitForEvent(ctx context.Context) (block.Message, error)
	}

	wfe, ok := s.vm.(waitForEventer)
	if !ok {
		return zapwire.MsgWaitForEvent, nil, fmt.Errorf("VM does not implement WaitForEvent")
	}

	msg, err := wfe.WaitForEvent(ctx)
	if err != nil {
		return zapwire.MsgWaitForEvent, nil, err
	}

	resp := &zapwire.WaitForEventResponse{
		Message: uint8(msg.Type),
	}

	buf := zapwire.GetBuffer()
	resp.Encode(buf)
	result := make([]byte, len(buf.Bytes()))
	copy(result, buf.Bytes())
	zapwire.PutBuffer(buf)

	return zapwire.MsgWaitForEvent, result, nil
}

func (s *zapVMServer) handleBatchedParseBlock(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.BatchedParseBlockRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgBatchedParseBlock, nil, err
	}

	resp := &zapwire.BatchedParseBlockResponse{
		Responses: make([]zapwire.BlockResponse, len(req.Requests)),
	}

	for i, blockBytes := range req.Requests {
		blk, err := s.vm.ParseBlock(ctx, blockBytes)
		if err != nil {
			resp.Responses[i] = zapwire.BlockResponse{
				Err: errorToZAP(err),
			}
			continue
		}

		blkID := blk.ID()
		parentID := blk.Parent()
		resp.Responses[i] = zapwire.BlockResponse{
			ID:        blkID[:],
			ParentID:  parentID[:],
			Bytes:     blk.Bytes(),
			Height:    blk.Height(),
			Timestamp: blk.Timestamp().UnixNano(),
			Err:       zapwire.ErrorUnspecified,
		}
	}

	buf := zapwire.GetBuffer()
	resp.Encode(buf)
	result := make([]byte, len(buf.Bytes()))
	copy(result, buf.Bytes())
	zapwire.PutBuffer(buf)

	return zapwire.MsgBatchedParseBlock, result, nil
}

func (s *zapVMServer) handleGetAncestors(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.GetAncestorsRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgGetAncestors, nil, err
	}

	blkID, err := ids.ToID(req.BlkID)
	if err != nil {
		return zapwire.MsgGetAncestors, nil, err
	}
	if req.MaxBlocksNum < 0 {
		return zapwire.MsgGetAncestors, nil, fmt.Errorf("getancestors: negative MaxBlocksNum %d", req.MaxBlocksNum)
	}

	ancestors := make([][]byte, 0, req.MaxBlocksNum)
	currentID := blkID

	for i := int32(0); i < req.MaxBlocksNum; i++ {
		blk, err := s.vm.GetBlock(ctx, currentID)
		if err != nil {
			break
		}
		ancestors = append(ancestors, blk.Bytes())
		currentID = blk.Parent()
	}

	resp := &zapwire.GetAncestorsResponse{
		BlksBytes: ancestors,
	}

	buf := zapwire.GetBuffer()
	resp.Encode(buf)
	result := make([]byte, len(buf.Bytes()))
	copy(result, buf.Bytes())
	zapwire.PutBuffer(buf)

	return zapwire.MsgGetAncestors, result, nil
}

func (s *zapVMServer) handleConnected(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.ConnectedRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgConnected, nil, err
	}
	s.logger.Debug("peer connected", "nodeID", fmt.Sprintf("%x", req.NodeID))
	return zapwire.MsgConnected, nil, nil
}

func (s *zapVMServer) handleDisconnected(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.DisconnectedRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgDisconnected, nil, err
	}
	s.logger.Debug("peer disconnected", "nodeID", fmt.Sprintf("%x", req.NodeID))
	return zapwire.MsgDisconnected, nil, nil
}

func (s *zapVMServer) handleGetBlockIDAtHeight(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.GetBlockIDAtHeightRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgGetBlockIDAtHeight, nil, err
	}

	type heightIndexer interface {
		GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error)
	}

	hi, ok := s.vm.(heightIndexer)
	if !ok {
		resp := &zapwire.GetBlockIDAtHeightResponse{
			Err: zapwire.ErrorNotFound,
		}
		buf := zapwire.GetBuffer()
		resp.Encode(buf)
		result := make([]byte, len(buf.Bytes()))
		copy(result, buf.Bytes())
		zapwire.PutBuffer(buf)
		return zapwire.MsgGetBlockIDAtHeight, result, nil
	}

	blkID, err := hi.GetBlockIDAtHeight(ctx, req.Height)
	if err != nil {
		resp := &zapwire.GetBlockIDAtHeightResponse{
			Err: errorToZAP(err),
		}
		buf := zapwire.GetBuffer()
		resp.Encode(buf)
		result := make([]byte, len(buf.Bytes()))
		copy(result, buf.Bytes())
		zapwire.PutBuffer(buf)
		return zapwire.MsgGetBlockIDAtHeight, result, nil
	}

	resp := &zapwire.GetBlockIDAtHeightResponse{
		BlkID: blkID[:],
		Err:   zapwire.ErrorUnspecified,
	}
	buf := zapwire.GetBuffer()
	resp.Encode(buf)
	result := make([]byte, len(buf.Bytes()))
	copy(result, buf.Bytes())
	zapwire.PutBuffer(buf)
	return zapwire.MsgGetBlockIDAtHeight, result, nil
}

func (s *zapVMServer) handleNewHTTPHandler(ctx context.Context) (zapwire.MessageType, []byte, error) {
	// Return empty response - main handlers are via CreateHandlers
	resp := &zapwire.NewHTTPHandlerResponse{}
	buf := zapwire.GetBuffer()
	resp.Encode(buf)
	result := make([]byte, len(buf.Bytes()))
	copy(result, buf.Bytes())
	zapwire.PutBuffer(buf)
	return zapwire.MsgNewHTTPHandler, result, nil
}

// handleSetQuasarFinalized applies a node-pushed Quasar (⅔-by-stake) EXPORT-FINAL
// height to the wrapped VM. Only reachable when the VM advertised CapQuasarExport
// (quasarVM != nil); a stray message on a non-capable VM is refused, not silently
// dropped. The response is empty — the node-side caller is fire-and-forget.
func (s *zapVMServer) handleSetQuasarFinalized(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	if s.quasarVM == nil {
		return zapwire.MsgSetQuasarFinalized, nil, fmt.Errorf("vm does not support quasar export")
	}
	req := &zapwire.SetQuasarFinalizedRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgSetQuasarFinalized, nil, fmt.Errorf("decode set-quasar-finalized: %w", err)
	}
	s.quasarVM.SetLastQuasarFinalized(req.Height)
	return zapwire.MsgSetQuasarFinalized, nil, nil
}

// handleQuasarHeight returns the wrapped VM's accept-tip-clamped Quasar
// EXPORT-FINAL height (0 before the first export). Only reachable when the VM
// advertised CapQuasarExport.
func (s *zapVMServer) handleQuasarHeight(ctx context.Context) (zapwire.MessageType, []byte, error) {
	if s.quasarVM == nil {
		return zapwire.MsgQuasarHeight, nil, fmt.Errorf("vm does not support quasar export")
	}
	resp := &zapwire.QuasarHeightResponse{Height: s.quasarVM.LastQuasarHeight()}
	buf := zapwire.GetBuffer()
	resp.Encode(buf)
	result := make([]byte, len(buf.Bytes()))
	copy(result, buf.Bytes())
	zapwire.PutBuffer(buf)
	return zapwire.MsgQuasarHeight, result, nil
}

func errorToZAP(err error) zapwire.Error {
	if err == nil {
		return zapwire.ErrorUnspecified
	}
	if err == database.ErrClosed {
		return zapwire.ErrorClosed
	}
	if err == database.ErrNotFound {
		return zapwire.ErrorNotFound
	}
	return zapwire.ErrorUnspecified
}
