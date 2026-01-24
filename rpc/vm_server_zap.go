//go:build !grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/database"
	"github.com/luxfi/log"
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
func Serve(ctx context.Context, logger log.Logger, vm chain.ChainVM) error {
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	// Track if shutdown is allowed
	allowShutdown := false

	// Get runtime address from ENV
	runtimeAddr := os.Getenv(runtime.EngineAddressKey)
	if runtimeAddr == "" {
		return fmt.Errorf("required env var missing: %q", runtime.EngineAddressKey)
	}
	logger.Info("vm.Serve: runtime address from env", "addr", runtimeAddr)

	// Create ZAP listener for RPC
	listener, err := zapwire.Listen("127.0.0.1:0", nil)
	if err != nil {
		return fmt.Errorf("failed to create ZAP listener: %w", err)
	}
	vmAddr := listener.Addr().String()
	logger.Info("vm.Serve: ZAP listener created", "addr", vmAddr)

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

	logger.Info("vm.Serve: handshake succeeded, starting ZAP server", "addr", vmAddr)

	// Create ZAP server for VM operations
	server := newZAPVMServer(vm, logger)
	zapServer := zapwire.NewServer(listener, server)

	// Handle shutdown signals in background
	go func() {
		for {
			select {
			case s := <-signals:
				if !allowShutdown {
					logger.Debug("vm server: ignoring signal (shutdown not allowed)", "signal", s)
					continue
				}
				switch s {
				case syscall.SIGINT:
					logger.Debug("vm server: ignoring SIGINT")
				case syscall.SIGTERM:
					logger.Info("vm server: received SIGTERM, shutting down")
					zapServer.Close()
					return
				}
			case <-ctx.Done():
				logger.Info("vm server: context cancelled")
				zapServer.Close()
				return
			}
		}
	}()

	// Serve requests (blocks until closed)
	return zapServer.Serve(ctx)
}

// zapVMServer implements zapwire.Handler for a VM
type zapVMServer struct {
	vm            chain.ChainVM
	logger        log.Logger
	allowShutdown *bool
}

func newZAPVMServer(vm chain.ChainVM, logger log.Logger) *zapVMServer {
	allowShutdown := false
	return &zapVMServer{
		vm:            vm,
		logger:        logger,
		allowShutdown: &allowShutdown,
	}
}

// Handle implements zapwire.Handler
func (s *zapVMServer) Handle(ctx context.Context, msgType zapwire.MessageType, payload []byte) (zapwire.MessageType, []byte, error) {
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
	default:
		return msgType, nil, fmt.Errorf("unknown message type: %d", msgType)
	}
}

func (s *zapVMServer) handleInitialize(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.InitializeRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgInitialize, nil, err
	}

	// Note: Full initialization requires chainCtx, db, etc. which aren't passed via ZAP yet
	// This is a simplified implementation - the VM should already be initialized by the runner
	lastAccepted, err := s.vm.LastAccepted(ctx)
	if err != nil {
		return zapwire.MsgInitialize, nil, err
	}

	resp := &zapwire.InitializeResponse{
		LastAcceptedID: lastAccepted[:],
		Height:         0, // Will be filled by actual implementation
	}

	buf := zapwire.GetBuffer()
	resp.Encode(buf)
	result := make([]byte, len(buf.Bytes()))
	copy(result, buf.Bytes())
	zapwire.PutBuffer(buf)

	return zapwire.MsgInitialize, result, nil
}

func (s *zapVMServer) handleShutdown(ctx context.Context) (zapwire.MessageType, []byte, error) {
	err := s.vm.Shutdown(ctx)
	return zapwire.MsgShutdown, nil, err
}

func (s *zapVMServer) handleSetState(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.SetStateRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgSetState, nil, err
	}

	// SetState takes uint32 directly
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

func (s *zapVMServer) handleBuildBlock(ctx context.Context) (zapwire.MessageType, []byte, error) {
	block, err := s.vm.BuildBlock(ctx)
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

	blkID := block.ID()
	parentID := block.Parent()
	resp := &zapwire.BlockResponse{
		ID:        blkID[:],
		ParentID:  parentID[:],
		Bytes:     block.Bytes(),
		Height:    block.Height(),
		Timestamp: block.Timestamp().UnixNano(),
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

	block, err := s.vm.ParseBlock(ctx, req.Bytes)
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

	blkID := block.ID()
	parentID := block.Parent()
	resp := &zapwire.BlockResponse{
		ID:        blkID[:],
		ParentID:  parentID[:],
		Bytes:     block.Bytes(),
		Height:    block.Height(),
		Timestamp: block.Timestamp().UnixNano(),
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

	var blkID [32]byte
	copy(blkID[:], req.ID)

	block, err := s.vm.GetBlock(ctx, blkID)
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

	retrievedBlkID := block.ID()
	parentID := block.Parent()
	resp := &zapwire.BlockResponse{
		ID:        retrievedBlkID[:],
		ParentID:  parentID[:],
		Bytes:     block.Bytes(),
		Height:    block.Height(),
		Timestamp: block.Timestamp().UnixNano(),
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

	var blkID [32]byte
	copy(blkID[:], req.ID)

	err := s.vm.SetPreference(ctx, blkID)
	return zapwire.MsgSetPreference, nil, err
}

func (s *zapVMServer) handleBlockVerify(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.BlockVerifyRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgBlockVerify, nil, err
	}

	// Parse and verify the block
	block, err := s.vm.ParseBlock(ctx, req.Bytes)
	if err != nil {
		return zapwire.MsgBlockVerify, nil, err
	}

	err = block.Verify(ctx)
	return zapwire.MsgBlockVerify, nil, err
}

func (s *zapVMServer) handleBlockAccept(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.BlockAcceptRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgBlockAccept, nil, err
	}

	var blkID [32]byte
	copy(blkID[:], req.ID)

	block, err := s.vm.GetBlock(ctx, blkID)
	if err != nil {
		return zapwire.MsgBlockAccept, nil, err
	}

	err = block.Accept(ctx)
	return zapwire.MsgBlockAccept, nil, err
}

func (s *zapVMServer) handleBlockReject(ctx context.Context, payload []byte) (zapwire.MessageType, []byte, error) {
	req := &zapwire.BlockRejectRequest{}
	if err := req.Decode(zapwire.NewReader(payload)); err != nil {
		return zapwire.MsgBlockReject, nil, err
	}

	var blkID [32]byte
	copy(blkID[:], req.ID)

	block, err := s.vm.GetBlock(ctx, blkID)
	if err != nil {
		return zapwire.MsgBlockReject, nil, err
	}

	err = block.Reject(ctx)
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

func errorToZAP(err error) zapwire.Error {
	if err == nil {
		return zapwire.ErrorUnspecified
	}
	// Check for common errors
	if err == database.ErrClosed {
		return zapwire.ErrorClosed
	}
	if err == database.ErrNotFound {
		return zapwire.ErrorNotFound
	}
	return zapwire.ErrorUnspecified
}
