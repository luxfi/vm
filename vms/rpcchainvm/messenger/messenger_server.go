// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package messenger

import (
	"context"
	"errors"

	consensuscore "github.com/luxfi/consensus/core"
	"github.com/luxfi/ids"

	messengerpb "github.com/luxfi/vm/proto/pb/messenger"
)

var (
	errFullQueue = errors.New("full message queue")

	_ messengerpb.MessengerServer = (*Server)(nil)
)

// Server is a messenger that is managed over RPC.
type Server struct {
	messengerpb.UnsafeMessengerServer
	messenger chan<- consensuscore.Message
}

// NewServer returns a messenger connected to a remote channel
func NewServer(messenger chan<- consensuscore.Message) *Server {
	return &Server{messenger: messenger}
}

func (s *Server) Notify(_ context.Context, req *messengerpb.NotifyRequest) (*messengerpb.NotifyResponse, error) {
	// Convert protobuf Message to consensuscore.Message
	var nodeID ids.NodeID
	copy(nodeID[:], req.Message.NodeId)

	msg := consensuscore.Message{
		Type:    consensuscore.MessageType(req.Message.Type),
		NodeID:  nodeID,
		Content: req.Message.Content,
	}

	select {
	case s.messenger <- msg:
		return &messengerpb.NotifyResponse{}, nil
	default:
		return nil, errFullQueue
	}
}
