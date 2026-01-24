//go:build grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sender

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/luxfi/ids"
	"github.com/luxfi/math/set"
	"github.com/luxfi/p2p"
	senderpb "github.com/luxfi/vm/proto/pb/sender"
)

var (
	_ senderpb.SenderServer = (*Server)(nil)
	_ SenderServer          = (*Server)(nil)
)

type Server struct {
	senderpb.UnimplementedSenderServer
	sender p2p.Sender
}

// NewServer returns a p2p.Sender server backed by gRPC
func NewServer(sender p2p.Sender) *Server {
	return &Server{sender: sender}
}

// GRPCRegistrar returns this server for gRPC registration.
func (s *Server) GRPCRegistrar() interface{} {
	return s
}

// ZAPHandler returns nil since this is a gRPC server.
func (s *Server) ZAPHandler() ZAPHandler {
	return nil
}

func (s *Server) SendRequest(ctx context.Context, req *senderpb.SendRequestMsg) (*emptypb.Empty, error) {
	nodeIDs := set.NewSet[ids.NodeID](len(req.NodeIds))
	for _, nodeIDBytes := range req.NodeIds {
		nodeID, err := ids.ToNodeID(nodeIDBytes)
		if err != nil {
			return nil, err
		}
		nodeIDs.Add(nodeID)
	}

	err := s.sender.SendRequest(ctx, nodeIDs, req.RequestId, req.Request)
	return &emptypb.Empty{}, err
}

func (s *Server) SendResponse(ctx context.Context, req *senderpb.SendResponseMsg) (*emptypb.Empty, error) {
	nodeID, err := ids.ToNodeID(req.NodeId)
	if err != nil {
		return nil, err
	}
	err = s.sender.SendResponse(ctx, nodeID, req.RequestId, req.Response)
	return &emptypb.Empty{}, err
}

func (s *Server) SendError(ctx context.Context, req *senderpb.SendErrorMsg) (*emptypb.Empty, error) {
	nodeID, err := ids.ToNodeID(req.NodeId)
	if err != nil {
		return nil, err
	}
	err = s.sender.SendError(ctx, nodeID, req.RequestId, req.ErrorCode, req.ErrorMessage)
	return &emptypb.Empty{}, err
}

func (s *Server) SendGossip(ctx context.Context, req *senderpb.SendGossipMsg) (*emptypb.Empty, error) {
	config := p2p.SendConfig{
		NodeIDs: set.NewSet[ids.NodeID](0),
	}
	err := s.sender.SendGossip(ctx, config, req.Msg)
	return &emptypb.Empty{}, err
}
