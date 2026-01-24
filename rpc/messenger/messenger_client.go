//go:build grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package messenger

import (
	"context"

	vmcore "github.com/luxfi/vm"

	messengerpb "github.com/luxfi/node/proto/pb/messenger"
)

// Client is an implementation of a messenger channel that talks over RPC.
type Client struct {
	client messengerpb.MessengerClient
}

// NewClient returns a client that is connected to a remote channel
func NewClient(client messengerpb.MessengerClient) *Client {
	return &Client{client: client}
}

func (c *Client) Notify(msg vmcore.Message) error {
	_, err := c.client.Notify(context.Background(), &messengerpb.NotifyRequest{
		Message: &messengerpb.Message{
			Type:    messengerpb.MessageType(msg.Type),
			NodeId:  msg.NodeID[:],
			Content: msg.Content,
		},
	})
	return err
}
