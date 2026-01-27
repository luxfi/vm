//go:build grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package gvalidators

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/luxfi/ids"
	validators "github.com/luxfi/validators"
	validatorstatepb "github.com/luxfi/node/proto/pb/validatorstate"
)

// NewClient creates a new validator state client
func NewClient(client validatorstatepb.ValidatorStateClient) validators.State {
	return &Client{client: client}
}

// Client is a ValidatorState client
type Client struct {
	client validatorstatepb.ValidatorStateClient
}

func (c *Client) GetCurrentHeight(ctx context.Context) (uint64, error) {
	resp, err := c.client.GetCurrentHeight(ctx, &emptypb.Empty{})
	if err != nil {
		return 0, err
	}
	return resp.Height, nil
}

func (c *Client) GetValidatorSet(ctx context.Context, height uint64, chainID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	resp, err := c.client.GetValidatorSet(ctx, &validatorstatepb.GetValidatorSetRequest{
		Height:  height,
		ChainId: chainID[:],
	})
	if err != nil {
		return nil, err
	}

	validatorSet := make(map[ids.NodeID]*validators.GetValidatorOutput, len(resp.Validators))
	for _, v := range resp.Validators {
		nodeID, err := ids.ToNodeID(v.NodeId)
		if err != nil {
			return nil, err
		}
		validatorSet[nodeID] = &validators.GetValidatorOutput{
			NodeID: nodeID,
			Light:  v.Weight,
			Weight: v.Weight, // Both fields for compatibility
		}
	}
	return validatorSet, nil
}

func (c *Client) GetCurrentValidators(ctx context.Context, height uint64, chainID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	// Call GetValidatorSet with the same parameters
	return c.GetValidatorSet(ctx, height, chainID)
}

func (c *Client) GetWarpValidatorSet(ctx context.Context, height uint64, chainID ids.ID) (*validators.WarpSet, error) {
	// Get the validator set at the requested height
	vdrSet, err := c.GetValidatorSet(ctx, height, chainID)
	if err != nil {
		return nil, err
	}

	// Convert to WarpSet format (Height + Validators map)
	warpValidators := make(map[ids.NodeID]*validators.WarpValidator, len(vdrSet))
	for nodeID, vdr := range vdrSet {
		// Only include validators with BLS public keys
		if len(vdr.PublicKey) > 0 {
			warpValidators[nodeID] = &validators.WarpValidator{
				NodeID:    nodeID,
				PublicKey: vdr.PublicKey,
				Weight:    vdr.Weight,
			}
		}
	}

	return &validators.WarpSet{
		Height:     height,
		Validators: warpValidators,
	}, nil
}

func (c *Client) GetWarpValidatorSets(ctx context.Context, heights []uint64, chainIDs []ids.ID) (map[ids.ID]map[uint64]*validators.WarpSet, error) {
	result := make(map[ids.ID]map[uint64]*validators.WarpSet)

	// For each chainID, get validator sets for all requested heights
	for _, chainID := range chainIDs {
		heightMap := make(map[uint64]*validators.WarpSet)
		for _, height := range heights {
			warpSet, err := c.GetWarpValidatorSet(ctx, height, chainID)
			if err != nil {
				return nil, err
			}
			heightMap[height] = warpSet
		}
		result[chainID] = heightMap
	}

	return result, nil
}

func (c *Client) GetMinimumHeight(ctx context.Context) (uint64, error) {
	// Return 0 as the minimum height - most implementations accept all heights
	return 0, nil
}

func (c *Client) GetChainID(netID ids.ID) (ids.ID, error) {
	// For the gRPC client, chain ID is typically the same as network ID
	// or can be looked up from the server if needed
	return netID, nil
}

func (c *Client) GetNetworkID(chainID ids.ID) (ids.ID, error) {
	// For the gRPC client, network ID is typically the same as chain ID
	// or can be looked up from the server if needed
	return chainID, nil
}
