// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package appsender

import (
	"context"

	"github.com/luxfi/ids"
	"github.com/luxfi/math/set"
	"github.com/luxfi/p2p"
	appsenderpb "github.com/luxfi/node/proto/pb/appsender"
)

var _ p2p.Sender = (*Client)(nil)

// NewClient returns a p2p.Sender backed by gRPC
func NewClient(client appsenderpb.AppSenderClient) p2p.Sender {
	return &Client{client: client}
}

// Client implements p2p.Sender over gRPC
type Client struct {
	client appsenderpb.AppSenderClient
}

func (c *Client) SendRequest(ctx context.Context, nodeIDs set.Set[ids.NodeID], requestID uint32, request []byte) error {
	nodeIDBytes := make([][]byte, 0, nodeIDs.Len())
	for nodeID := range nodeIDs {
		nodeIDBytes = append(nodeIDBytes, nodeID[:])
	}
	_, err := c.client.SendAppRequest(ctx, &appsenderpb.SendAppRequestMsg{
		NodeIds:   nodeIDBytes,
		RequestId: requestID,
		Request:   request,
	})
	return err
}

func (c *Client) SendResponse(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error {
	_, err := c.client.SendAppResponse(ctx, &appsenderpb.SendAppResponseMsg{
		NodeId:    nodeID[:],
		RequestId: requestID,
		Response:  response,
	})
	return err
}

func (c *Client) SendError(ctx context.Context, nodeID ids.NodeID, requestID uint32, errorCode int32, errorMessage string) error {
	_, err := c.client.SendAppError(ctx, &appsenderpb.SendAppErrorMsg{
		NodeId:       nodeID[:],
		RequestId:    requestID,
		ErrorCode:    errorCode,
		ErrorMessage: errorMessage,
	})
	return err
}

func (c *Client) SendGossip(ctx context.Context, config p2p.SendConfig, msg []byte) error {
	_, err := c.client.SendAppGossip(ctx, &appsenderpb.SendAppGossipMsg{
		Msg: msg,
	})
	return err
}
