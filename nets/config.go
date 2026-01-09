// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package nets

import (
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/consensus/config"
	"github.com/luxfi/ids"
	"github.com/luxfi/math/set"
)

var errAllowedNodesWhenNotValidatorOnly = errors.New("allowedNodes can only be set when ValidatorOnly is true")

type Config struct {
	// ValidatorOnly indicates that this Net's Chains are available to only net validators.
	// No chain related messages will go out to non-validators.
	// Validators will drop messages received from non-validators.
	// Also see [AllowedNodes] to allow non-validators to connect to this Net.
	ValidatorOnly bool `json:"validatorOnly" yaml:"validatorOnly"`
	// AllowedNodes is the set of node IDs that are explicitly allowed to connect to this Net when
	// ValidatorOnly is enabled.
	AllowedNodes        set.Set[ids.NodeID] `json:"allowedNodes"        yaml:"allowedNodes"`
	ConsensusParameters config.Parameters   `json:"consensusParameters" yaml:"consensusParameters"`

	// ProposerMinBlockDelay is the minimum delay this node will enforce when
	// building a linear++ block.
	//
	ProposerMinBlockDelay time.Duration `json:"proposerMinBlockDelay" yaml:"proposerMinBlockDelay"`
	// ProposerNumHistoricalBlocks is the number of historical linear++ blocks
	// this node will index per chain. If set to 0, the node will index all
	// linear++ blocks.
	//
	// Note: The last accepted block is not considered a historical block. This
	// prevents the user from only storing the last accepted block, which can
	// never be safe due to the non-atomic commits between the proposervm
	// database and the innerVM's database.
	//
	// Invariant: This value must be set such that the proposervm never needs to
	// rollback more blocks than have been deleted. On startup, the proposervm
	// rolls back its accepted chain to match the innerVM's accepted chain. If
	// the innerVM is not persisting its last accepted block quickly enough, the
	// database can become corrupted.
	//
	// basis.
	ProposerNumHistoricalBlocks uint64 `json:"proposerNumHistoricalBlocks" yaml:"proposerNumHistoricalBlocks"`

	// POA Mode Configuration
	POAEnabled        bool          `json:"poaEnabled" yaml:"poaEnabled"`
	POASingleNodeMode bool          `json:"poaSingleNodeMode" yaml:"poaSingleNodeMode"`
	POAMinBlockTime   time.Duration `json:"poaMinBlockTime" yaml:"poaMinBlockTime"`
}

func (c *Config) Valid() error {
	if err := c.ConsensusParameters.Validate(); err != nil {
		return fmt.Errorf("%w: %w", config.ErrParametersInvalid, err)
	}
	if !c.ValidatorOnly && c.AllowedNodes.Len() > 0 {
		return errAllowedNodesWhenNotValidatorOnly
	}
	return nil
}

// GetPOAConsensusParameters returns sampling parameters optimized for POA mode
func GetPOAConsensusParameters() config.Parameters {
	return config.Parameters{
		K:                     1,   // Only query 1 node (ourselves)
		Alpha:                 1.0, // Required: must be between 0.5 and 1.0
		AlphaPreference:       1,   // Change preference with 1 vote
		AlphaConfidence:       1,   // Increase confidence with 1 vote
		Beta:                  1,   // Only need 1 successful query for finalization
		ConcurrentPolls:       1,   // Only 1 concurrent poll needed
		OptimalProcessing:     1,   // Single-node POA mode: only 1 block in processing
		MaxOutstandingItems:   256,
		MaxItemProcessingTime: 30 * time.Second,
	}
}
