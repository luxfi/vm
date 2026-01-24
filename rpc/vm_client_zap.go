//go:build !grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"context"
	"fmt"
	"time"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/metric"
	"github.com/luxfi/resource"
	"github.com/luxfi/vm/chain"
	"github.com/luxfi/vm/rpc/runtime"
)

// ZAPClient implements the VM interface over ZAP transport
type ZAPClient struct {
	conn   *zapwire.Conn
	logger log.Logger

	runtime        runtime.Stopper
	pid            int
	processTracker resource.ProcessTracker

	// Cached state from Initialize
	lastAcceptedID ids.ID
}

// NewZAPClient creates a new ZAP-based VM client
func NewZAPClient(
	conn *zapwire.Conn,
	stopper runtime.Stopper,
	pid int,
	processTracker resource.ProcessTracker,
	metricsGatherer metric.MultiGatherer,
	logger log.Logger,
) *ZAPClient {
	return &ZAPClient{
		conn:           conn,
		runtime:        stopper,
		pid:            pid,
		processTracker: processTracker,
		logger:         logger,
	}
}

// Initialize implements chain.ChainVM
func (c *ZAPClient) Initialize(
	ctx context.Context,
	chainCtx interface{},
	db interface{},
	genesisBytes, upgradeBytes, configBytes []byte,
	msgChan interface{},
	fxs []interface{},
	sender interface{},
) error {
	req := &zapwire.InitializeRequest{
		GenesisBytes: genesisBytes,
		UpgradeBytes: upgradeBytes,
		ConfigBytes:  configBytes,
	}

	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	req.Encode(buf)

	respType, respData, err := c.conn.Call(ctx, zapwire.MsgInitialize, buf.Bytes())
	if err != nil {
		return fmt.Errorf("zap initialize: %w", err)
	}

	if respType&^zapwire.MsgResponseFlag != zapwire.MsgInitialize {
		return fmt.Errorf("unexpected response type: %d", respType)
	}

	resp := &zapwire.InitializeResponse{}
	if err := resp.Decode(zapwire.NewReader(respData)); err != nil {
		return fmt.Errorf("zap decode initialize response: %w", err)
	}

	copy(c.lastAcceptedID[:], resp.LastAcceptedID)

	c.logger.Info("VM initialized via ZAP",
		"height", resp.Height,
		"lastAcceptedID", c.lastAcceptedID,
	)

	return nil
}

// Shutdown implements chain.ChainVM
func (c *ZAPClient) Shutdown(ctx context.Context) error {
	_, _, err := c.conn.Call(ctx, zapwire.MsgShutdown, nil)
	if err != nil {
		c.logger.Warn("ZAP shutdown error", "error", err)
	}
	c.conn.Close()
	c.runtime.Stop(ctx)
	return err
}

// SetState implements chain.ChainVM
func (c *ZAPClient) SetState(ctx context.Context, state uint32) error {
	req := &zapwire.SetStateRequest{
		State: zapwire.State(state),
	}

	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	req.Encode(buf)

	_, _, err := c.conn.Call(ctx, zapwire.MsgSetState, buf.Bytes())
	return err
}

// Version implements chain.ChainVM
func (c *ZAPClient) Version(ctx context.Context) (string, error) {
	_, respData, err := c.conn.Call(ctx, zapwire.MsgVersion, nil)
	if err != nil {
		return "", err
	}

	resp := &zapwire.VersionResponse{}
	if err := resp.Decode(zapwire.NewReader(respData)); err != nil {
		return "", err
	}

	return resp.Version, nil
}

// BuildBlock implements chain.ChainVM
func (c *ZAPClient) BuildBlock(ctx context.Context) (chain.Block, error) {
	_, respData, err := c.conn.Call(ctx, zapwire.MsgBuildBlock, nil)
	if err != nil {
		return nil, err
	}

	resp := &zapwire.BlockResponse{}
	if err := resp.Decode(zapwire.NewReader(respData)); err != nil {
		return nil, err
	}

	if resp.Err != zapwire.ErrorUnspecified {
		return nil, errorFromZAP(resp.Err)
	}

	var id, parentID ids.ID
	copy(id[:], resp.ID)
	copy(parentID[:], resp.ParentID)

	return &zapBlock{
		client:    c,
		id:        id,
		parentID:  parentID,
		bytes:     resp.Bytes,
		height:    resp.Height,
		timestamp: time.Unix(0, resp.Timestamp),
	}, nil
}

// ParseBlock implements chain.ChainVM
func (c *ZAPClient) ParseBlock(ctx context.Context, blockBytes []byte) (chain.Block, error) {
	req := &zapwire.ParseBlockRequest{
		Bytes: blockBytes,
	}

	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	req.Encode(buf)

	_, respData, err := c.conn.Call(ctx, zapwire.MsgParseBlock, buf.Bytes())
	if err != nil {
		return nil, err
	}

	resp := &zapwire.BlockResponse{}
	if err := resp.Decode(zapwire.NewReader(respData)); err != nil {
		return nil, err
	}

	if resp.Err != zapwire.ErrorUnspecified {
		return nil, errorFromZAP(resp.Err)
	}

	var id, parentID ids.ID
	copy(id[:], resp.ID)
	copy(parentID[:], resp.ParentID)

	return &zapBlock{
		client:    c,
		id:        id,
		parentID:  parentID,
		bytes:     blockBytes, // Use original bytes
		height:    resp.Height,
		timestamp: time.Unix(0, resp.Timestamp),
	}, nil
}

// GetBlock implements chain.ChainVM
func (c *ZAPClient) GetBlock(ctx context.Context, blkID ids.ID) (chain.Block, error) {
	req := &zapwire.GetBlockRequest{
		ID: blkID[:],
	}

	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	req.Encode(buf)

	_, respData, err := c.conn.Call(ctx, zapwire.MsgGetBlock, buf.Bytes())
	if err != nil {
		return nil, err
	}

	resp := &zapwire.BlockResponse{}
	if err := resp.Decode(zapwire.NewReader(respData)); err != nil {
		return nil, err
	}

	if resp.Err != zapwire.ErrorUnspecified {
		return nil, errorFromZAP(resp.Err)
	}

	var parentID ids.ID
	copy(parentID[:], resp.ParentID)

	return &zapBlock{
		client:    c,
		id:        blkID,
		parentID:  parentID,
		bytes:     resp.Bytes,
		height:    resp.Height,
		timestamp: time.Unix(0, resp.Timestamp),
	}, nil
}

// SetPreference implements chain.ChainVM
func (c *ZAPClient) SetPreference(ctx context.Context, blkID ids.ID) error {
	req := &zapwire.SetPreferenceRequest{
		ID: blkID[:],
	}

	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	req.Encode(buf)

	_, _, err := c.conn.Call(ctx, zapwire.MsgSetPreference, buf.Bytes())
	return err
}

// LastAccepted implements chain.ChainVM
func (c *ZAPClient) LastAccepted(ctx context.Context) (ids.ID, error) {
	return c.lastAcceptedID, nil
}

// zapBlock implements chain.Block
type zapBlock struct {
	client    *ZAPClient
	id        ids.ID
	parentID  ids.ID
	bytes     []byte
	height    uint64
	timestamp time.Time
}

func (b *zapBlock) ID() ids.ID           { return b.id }
func (b *zapBlock) Parent() ids.ID       { return b.parentID }
func (b *zapBlock) ParentID() ids.ID     { return b.parentID }
func (b *zapBlock) Bytes() []byte        { return b.bytes }
func (b *zapBlock) Height() uint64       { return b.height }
func (b *zapBlock) Timestamp() time.Time { return b.timestamp }
func (b *zapBlock) Status() uint8        { return uint8(chain.Processing) }

func (b *zapBlock) Verify(ctx context.Context) error {
	req := &zapwire.BlockVerifyRequest{
		Bytes:           b.bytes,
		HasPChainHeight: false,
	}

	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	req.Encode(buf)

	_, _, err := b.client.conn.Call(ctx, zapwire.MsgBlockVerify, buf.Bytes())
	return err
}

func (b *zapBlock) Accept(ctx context.Context) error {
	req := &zapwire.BlockAcceptRequest{
		ID: b.id[:],
	}

	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	req.Encode(buf)

	_, _, err := b.client.conn.Call(ctx, zapwire.MsgBlockAccept, buf.Bytes())
	return err
}

func (b *zapBlock) Reject(ctx context.Context) error {
	req := &zapwire.BlockRejectRequest{
		ID: b.id[:],
	}

	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	req.Encode(buf)

	_, _, err := b.client.conn.Call(ctx, zapwire.MsgBlockReject, buf.Bytes())
	return err
}

func errorFromZAP(err zapwire.Error) error {
	switch err {
	case zapwire.ErrorUnspecified:
		return nil
	case zapwire.ErrorClosed:
		return database.ErrClosed
	case zapwire.ErrorNotFound:
		return database.ErrNotFound
	default:
		return fmt.Errorf("zap error: %d", err)
	}
}
