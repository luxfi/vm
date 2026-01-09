// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package appsender

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/luxfi/ids"
	"github.com/luxfi/math/set"
	appsenderpb "github.com/luxfi/vm/proto/pb/appsender"
	"github.com/luxfi/warp"
)

var _ appsenderpb.AppSenderServer = (*Server)(nil)

type Server struct {
	appsenderpb.UnsafeAppSenderServer
	sender warp.Sender
}

// NewServer returns a messenger connected to a remote channel
func NewServer(sender warp.Sender) *Server {
	return &Server{sender: sender}
}

func (s *Server) SendAppRequest(ctx context.Context, req *appsenderpb.SendAppRequestMsg) (*emptypb.Empty, error) {
	// Convert byte slices to NodeID set
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

func (s *Server) SendAppResponse(ctx context.Context, req *appsenderpb.SendAppResponseMsg) (*emptypb.Empty, error) {
	nodeID, err := ids.ToNodeID(req.NodeId)
	if err != nil {
		return nil, err
	}
	err = s.sender.SendResponse(ctx, nodeID, req.RequestId, req.Response)
	return &emptypb.Empty{}, err
}

func (s *Server) SendAppError(ctx context.Context, req *appsenderpb.SendAppErrorMsg) (*emptypb.Empty, error) {
	nodeID, err := ids.ToNodeID(req.NodeId)
	if err != nil {
		return nil, err
	}

	err = s.sender.SendError(ctx, nodeID, req.RequestId, req.ErrorCode, req.ErrorMessage)
	return &emptypb.Empty{}, err
}

func (s *Server) SendAppGossip(ctx context.Context, req *appsenderpb.SendAppGossipMsg) (*emptypb.Empty, error) {
	// For RPC gossip, we don't have specific nodes, so use an empty config
	config := warp.SendConfig{
		NodeIDs: set.NewSet[ids.NodeID](0),
	}
	err := s.sender.SendGossip(ctx, config, req.Msg)
	return &emptypb.Empty{}, err
}

// SendCrossChainAppRequest implements AppSenderServer
func (s *Server) SendCrossChainAppRequest(ctx context.Context, req *appsenderpb.SendCrossChainAppRequestMsg) (*emptypb.Empty, error) {
	// Not implemented in warp.Sender
	return &emptypb.Empty{}, nil
}

// SendCrossChainAppResponse implements AppSenderServer
func (s *Server) SendCrossChainAppResponse(ctx context.Context, req *appsenderpb.SendCrossChainAppResponseMsg) (*emptypb.Empty, error) {
	// Not implemented in warp.Sender
	return &emptypb.Empty{}, nil
}

// SendCrossChainAppError implements AppSenderServer
func (s *Server) SendCrossChainAppError(ctx context.Context, req *appsenderpb.SendCrossChainAppErrorMsg) (*emptypb.Empty, error) {
	// Not implemented in warp.Sender
	return &emptypb.Empty{}, nil
}
