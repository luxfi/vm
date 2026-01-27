//go:build grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package gvalidators

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/luxfi/ids"
	validators "github.com/luxfi/validators"

	pb "github.com/luxfi/node/proto/pb/validatorstate"
)

var _ pb.ValidatorStateServer = (*Server)(nil)

type Server struct {
	pb.UnsafeValidatorStateServer
	state validators.State
}

func NewServer(state validators.State) *Server {
	return &Server{state: state}
}

func (s *Server) GetMinimumHeight(ctx context.Context, _ *emptypb.Empty) (*pb.GetMinimumHeightResponse, error) {
	// validators.State doesn't have GetMinimumHeight - return 0
	return &pb.GetMinimumHeightResponse{Height: 0}, nil
}

func (s *Server) GetCurrentHeight(ctx context.Context, _ *emptypb.Empty) (*pb.GetCurrentHeightResponse, error) {
	height, err := s.state.GetCurrentHeight(ctx)
	return &pb.GetCurrentHeightResponse{Height: height}, err
}

func (s *Server) GetChainID(ctx context.Context, req *pb.GetChainIDRequest) (*pb.GetChainIDResponse, error) {
	// validators.State doesn't have GetChainID - return empty ID
	return &pb.GetChainIDResponse{
		ChainId: ids.Empty[:],
	}, nil
}

func (s *Server) GetValidatorSet(ctx context.Context, req *pb.GetValidatorSetRequest) (*pb.GetValidatorSetResponse, error) {
	chainID, err := ids.ToID(req.ChainId)
	if err != nil {
		return nil, err
	}

	// GetValidatorSet returns map[ids.NodeID]*GetValidatorOutput
	validators, err := s.state.GetValidatorSet(ctx, req.Height, chainID)
	if err != nil {
		return nil, err
	}

	resp := &pb.GetValidatorSetResponse{
		Validators: make([]*pb.Validator, 0, len(validators)),
	}

	for nodeID, validator := range validators {
		vdrPB := &pb.Validator{
			NodeId: nodeID.Bytes(),
			Weight: validator.Light, // Use Light field which is the actual weight
		}
		resp.Validators = append(resp.Validators, vdrPB)
	}
	return resp, nil
}

func (s *Server) GetCurrentValidatorSet(ctx context.Context, req *pb.GetCurrentValidatorSetRequest) (*pb.GetCurrentValidatorSetResponse, error) {
	chainID, err := ids.ToID(req.ChainId)
	if err != nil {
		return nil, err
	}

	// validators.State doesn't have GetCurrentValidatorSet, use GetValidatorSet with current height
	currentHeight, err := s.state.GetCurrentHeight(ctx)
	if err != nil {
		return nil, err
	}

	validators, err := s.state.GetValidatorSet(ctx, currentHeight, chainID)
	if err != nil {
		return nil, err
	}

	resp := &pb.GetCurrentValidatorSetResponse{
		Validators:    make([]*pb.Validator, 0, len(validators)),
		CurrentHeight: currentHeight,
	}

	for nodeID, validator := range validators {
		vdrPB := &pb.Validator{
			NodeId: nodeID.Bytes(),
			Weight: validator.Light, // Use Light field which is the actual weight
			// All other fields like StartTime, IsActive, etc. are not available
		}
		resp.Validators = append(resp.Validators, vdrPB)
	}
	return resp, nil
}
