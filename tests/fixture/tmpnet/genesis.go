// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2019-2024, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package tmpnet

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/luxfi/constantsants"
	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/utils/units"
)

// GenesisConfig represents genesis configuration
type GenesisConfig struct {
	NetworkID                  uint32       `json:"networkID"`
	Allocations                []Allocation `json:"allocations"`
	StartTime                  uint64       `json:"startTime"`
	InitialStakeDuration       uint64       `json:"initialStakeDuration"`
	InitialStakeDurationOffset uint64       `json:"initialStakeDurationOffset"`
	InitialStakedFunds         []string     `json:"initialStakedFunds"`
	InitialStakers             []Staker     `json:"initialStakers"`
	CChainGenesis              string       `json:"cChainGenesis"`
	Message                    string       `json:"message"`
}

// Allocation represents an initial fund allocation
type Allocation struct {
	ETHAddr        string         `json:"ethAddr"`
	LUXAddr        string         `json:"luxAddr"`
	InitialAmount  uint64         `json:"initialAmount"`
	UnlockSchedule []UnlockPeriod `json:"unlockSchedule,omitempty"`
}

// UnlockPeriod represents a vesting unlock period
type UnlockPeriod struct {
	Amount   uint64 `json:"amount"`
	Locktime uint64 `json:"locktime"`
}

// Staker represents an initial staker
type Staker struct {
	NodeID        string `json:"nodeID"`
	RewardAddress string `json:"rewardAddress"`
	DelegationFee uint32 `json:"delegationFee"`
}

// NewTestGenesisWithFunds creates a test genesis configuration with funded accounts
func NewTestGenesisWithFunds(
	networkID uint32,
	nodes []*Node,
	fundedKeys []*secp256k1.PrivateKey,
) ([]byte, error) {
	startTime := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)

	config := GenesisConfig{
		NetworkID:                  networkID,
		StartTime:                  uint64(startTime.Unix()),
		InitialStakeDuration:       uint64((365 * 24 * time.Hour).Seconds()),
		InitialStakeDurationOffset: 0,
		Message:                    "LUX Test Genesis",
	}

	// Add allocations for funded keys
	for _, key := range fundedKeys {
		addr := key.Address()
		allocation := Allocation{
			LUXAddr:       addr.String(),
			InitialAmount: 300 * units.MegaLux, // 300M LUX per funded key
		}
		config.Allocations = append(config.Allocations, allocation)
		config.InitialStakedFunds = append(config.InitialStakedFunds, addr.String())
	}

	// Add initial stakers from nodes
	for _, node := range nodes {
		if node.NodeID != ids.EmptyNodeID {
			staker := Staker{
				NodeID:        node.NodeID.String(),
				DelegationFee: 20000, // 2%
			}
			if len(fundedKeys) > 0 {
				staker.RewardAddress = fundedKeys[0].Address().String()
			}
			config.InitialStakers = append(config.InitialStakers, staker)
		}
	}

	// Add basic C-Chain genesis
	config.CChainGenesis = getBasicCChainGenesis(networkID)

	return json.MarshalIndent(config, "", "  ")
}

// getBasicCChainGenesis returns a basic C-Chain genesis configuration
func getBasicCChainGenesis(networkID uint32) string {
	chainID := int64(networkID)

	genesis := map[string]interface{}{
		"config": map[string]interface{}{
			"chainId":                         chainID,
			"homesteadBlock":                  0,
			"eip150Block":                     0,
			"eip155Block":                     0,
			"eip158Block":                     0,
			"byzantiumBlock":                  0,
			"constantinopleBlock":             0,
			"petersburgBlock":                 0,
			"istanbulBlock":                   0,
			"muirGlacierBlock":                0,
			"apricotPhase1BlockTimestamp":     0,
			"apricotPhase2BlockTimestamp":     0,
			"apricotPhase3BlockTimestamp":     0,
			"apricotPhase4BlockTimestamp":     0,
			"apricotPhase5BlockTimestamp":     0,
			"apricotPhasePre6BlockTimestamp":  0,
			"apricotPhase6BlockTimestamp":     0,
			"apricotPhasePost6BlockTimestamp": 0,
			"banffBlockTimestamp":             0,
			"cortinaBlockTimestamp":           0,
			"durangoBlockTimestamp":           0,
			"etnaTimestamp":                   0,
		},
		"nonce":      "0x0",
		"timestamp":  "0x0",
		"extraData":  "0x00",
		"gasLimit":   fmt.Sprintf("0x%x", 8000000),
		"difficulty": "0x1",
		"mixHash":    "0x0000000000000000000000000000000000000000000000000000000000000000",
		"coinbase":   "0x0000000000000000000000000000000000000000",
		"alloc":      map[string]interface{}{},
		"number":     "0x0",
		"gasUsed":    "0x0",
		"parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
	}

	data, _ := json.Marshal(genesis)
	return string(data)
}

// ValidateGenesis validates a genesis configuration
func ValidateGenesis(genesisBytes []byte) error {
	var config GenesisConfig
	if err := json.Unmarshal(genesisBytes, &config); err != nil {
		return fmt.Errorf("failed to parse genesis config: %w", err)
	}

	if config.NetworkID == 0 {
		return fmt.Errorf("network ID must be set")
	}

	if config.StartTime == 0 {
		return fmt.Errorf("start time must be set")
	}

	// Validate allocations
	for i, alloc := range config.Allocations {
		if alloc.LUXAddr == "" && alloc.ETHAddr == "" {
			return fmt.Errorf("allocation %d has no address", i)
		}
	}

	return nil
}

// GetDefaultNetworkID returns the default network ID for testing
func GetDefaultNetworkID() uint32 {
	return constants.CustomID
}
