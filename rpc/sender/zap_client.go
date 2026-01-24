// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sender

import (
	"context"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/ids"
	"github.com/luxfi/math/set"
	"github.com/luxfi/p2p"
)

var _ p2p.Sender = (*zapClient)(nil)

// zapClient implements p2p.Sender over ZAP transport
type zapClient struct {
	conn *zapwire.Conn
}

// ZAP returns a p2p.Sender using ZAP transport.
func ZAP(conn *zapwire.Conn) p2p.Sender {
	return &zapClient{conn: conn}
}

// NewZAPClient is an alias for ZAP for backwards compatibility.
// Deprecated: Use ZAP() instead.
func NewZAPClient(conn *zapwire.Conn) p2p.Sender {
	return ZAP(conn)
}

func (c *zapClient) SendRequest(ctx context.Context, nodeIDs set.Set[ids.NodeID], requestID uint32, request []byte) error {
	nodeIDBytes := make([][]byte, 0, nodeIDs.Len())
	for nodeID := range nodeIDs {
		nodeIDBytes = append(nodeIDBytes, nodeID[:])
	}

	msg := &zapwire.SendRequestMsg{
		NodeIDs:   nodeIDBytes,
		RequestID: requestID,
		Request:   request,
	}

	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	msg.Encode(buf)

	return c.conn.Send(zapwire.MsgSendRequest, buf.Bytes())
}

func (c *zapClient) SendResponse(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error {
	msg := &zapwire.SendResponseMsg{
		NodeID:    nodeID[:],
		RequestID: requestID,
		Response:  response,
	}

	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	msg.Encode(buf)

	return c.conn.Send(zapwire.MsgSendResponse, buf.Bytes())
}

func (c *zapClient) SendError(ctx context.Context, nodeID ids.NodeID, requestID uint32, errorCode int32, errorMessage string) error {
	msg := &zapwire.SendErrorMsg{
		NodeID:       nodeID[:],
		RequestID:    requestID,
		ErrorCode:    errorCode,
		ErrorMessage: errorMessage,
	}

	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	msg.Encode(buf)

	return c.conn.Send(zapwire.MsgSendError, buf.Bytes())
}

func (c *zapClient) SendGossip(ctx context.Context, config p2p.SendConfig, msg []byte) error {
	nodeIDBytes := make([][]byte, 0, config.NodeIDs.Len())
	for nodeID := range config.NodeIDs {
		nodeIDBytes = append(nodeIDBytes, nodeID[:])
	}

	gossipMsg := &zapwire.SendGossipMsg{
		NodeIDs:       nodeIDBytes,
		Validators:    uint64(config.Validators),
		NonValidators: uint64(config.NonValidators),
		Peers:         uint64(config.Peers),
		Msg:           msg,
	}

	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	gossipMsg.Encode(buf)

	return c.conn.Send(zapwire.MsgSendGossip, buf.Bytes())
}
