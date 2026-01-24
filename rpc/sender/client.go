//go:build grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sender

import (
	"context"

	"github.com/luxfi/ids"
	"github.com/luxfi/math/set"
	"github.com/luxfi/p2p"
	senderpb "github.com/luxfi/vm/proto/pb/sender"
)

var _ p2p.Sender = (*grpcClient)(nil)

// grpcClient implements p2p.Sender over gRPC
type grpcClient struct {
	client senderpb.SenderClient
}

// GRPC returns a p2p.Sender using gRPC transport.
func GRPC(client senderpb.SenderClient) p2p.Sender {
	return &grpcClient{client: client}
}

// NewClient is an alias for GRPC for backwards compatibility.
// Deprecated: Use GRPC() instead.
func NewClient(client senderpb.SenderClient) p2p.Sender {
	return GRPC(client)
}

func (c *grpcClient) SendRequest(ctx context.Context, nodeIDs set.Set[ids.NodeID], requestID uint32, request []byte) error {
	nodeIDBytes := make([][]byte, 0, nodeIDs.Len())
	for nodeID := range nodeIDs {
		nodeIDBytes = append(nodeIDBytes, nodeID[:])
	}
	_, err := c.client.SendRequest(ctx, &senderpb.SendRequestMsg{
		NodeIds:   nodeIDBytes,
		RequestId: requestID,
		Request:   request,
	})
	return err
}

func (c *grpcClient) SendResponse(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error {
	_, err := c.client.SendResponse(ctx, &senderpb.SendResponseMsg{
		NodeId:    nodeID[:],
		RequestId: requestID,
		Response:  response,
	})
	return err
}

func (c *grpcClient) SendError(ctx context.Context, nodeID ids.NodeID, requestID uint32, errorCode int32, errorMessage string) error {
	_, err := c.client.SendError(ctx, &senderpb.SendErrorMsg{
		NodeId:       nodeID[:],
		RequestId:    requestID,
		ErrorCode:    errorCode,
		ErrorMessage: errorMessage,
	})
	return err
}

func (c *grpcClient) SendGossip(ctx context.Context, config p2p.SendConfig, msg []byte) error {
	_, err := c.client.SendGossip(ctx, &senderpb.SendGossipMsg{
		Msg: msg,
	})
	return err
}
