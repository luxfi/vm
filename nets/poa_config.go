// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.


package nets

import (
	"time"

	"github.com/luxfi/consensus/config"
)

// POAConfig provides Proof of Authority configuration for subnets
type POAConfig struct {
	// Enabled indicates if POA mode is active
	Enabled bool `json:"enabled" yaml:"enabled"`

	// SingleNodeMode allows a single node to produce and finalize blocks
	SingleNodeMode bool `json:"singleNodeMode" yaml:"singleNodeMode"`

	// MinBlockTime is the minimum time between blocks in POA mode
	MinBlockTime time.Duration `json:"minBlockTime" yaml:"minBlockTime"`

	// AuthorizedNodes are the nodes authorized to produce blocks
	AuthorizedNodes []string `json:"authorizedNodes" yaml:"authorizedNodes"`
}

// DefaultPOAParameters returns sampling parameters optimized for POA mode
func DefaultPOAParameters() config.Parameters {
	return config.Parameters{
		K:                     1, // Only query 1 node (ourselves)
		AlphaPreference:       1, // Change preference with 1 vote
		AlphaConfidence:       1, // Increase confidence with 1 vote
		Beta:                  1, // Only need 1 successful query for finalization
		ConcurrentPolls:       1, // Only 1 concurrent poll needed
		OptimalProcessing:     1, // Only 1 block in processing at a time for single-node mode
		MaxOutstandingItems:   256,
		MaxItemProcessingTime: 30 * time.Second,
	}
}

// ApplyPOAConfig modifies the net config for POA mode
func (c *Config) ApplyPOAConfig(poa POAConfig) {
	if !poa.Enabled {
		return
	}

	// Override consensus parameters for POA
	c.ConsensusParameters = DefaultPOAParameters()

	// Set minimum block delay for POA
	if poa.MinBlockTime > 0 {
		c.ProposerMinBlockDelay = poa.MinBlockTime
	} else {
		c.ProposerMinBlockDelay = 1 * time.Second // Default 1 second blocks
	}

	// In POA mode, we don't need to store many historical blocks
	c.ProposerNumHistoricalBlocks = 100
}
