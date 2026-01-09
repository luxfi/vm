// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package api

import (
	"github.com/luxfi/ids"

	"github.com/luxfi/vm/utils/json"
	"github.com/luxfi/vm/vms/platformvm/signer"
)

// UTXO is a UTXO on the Platform Chain that exists at the chain's genesis.
type UTXO struct {
	Locktime json.Uint64 `json:"locktime"`
	Amount   json.Uint64 `json:"amount"`
	Address  string      `json:"address"`
	Message  string      `json:"message"`
}

// Staker is the representation of a staker sent via APIs.
type Staker struct {
	TxID      ids.ID      `json:"txID"`
	StartTime json.Uint64 `json:"startTime"`
	EndTime   json.Uint64 `json:"endTime"`
	Weight    json.Uint64 `json:"weight"`
	NodeID    ids.NodeID  `json:"nodeID"`

	// Deprecated: Use Weight instead
	StakeAmount *json.Uint64 `json:"stakeAmount,omitempty"`
}

// GenesisValidator should be used for genesis validators only.
type GenesisValidator Staker

// Owner is the repr. of a reward owner sent over APIs.
type Owner struct {
	Locktime  json.Uint64 `json:"locktime"`
	Threshold json.Uint32 `json:"threshold"`
	Addresses []string    `json:"addresses"`
}

// PermissionlessValidator is the repr. of a permissionless validator sent over APIs.
type PermissionlessValidator struct {
	Staker
	BaseL1Validator
	// Deprecated: RewardOwner has been replaced by ValidationRewardOwner and DelegationRewardOwner.
	RewardOwner *Owner `json:"rewardOwner,omitempty"`
	// The owner of the rewards from the validation period, if applicable.
	ValidationRewardOwner *Owner `json:"validationRewardOwner,omitempty"`
	// The owner of the rewards from delegations during the validation period, if applicable.
	DelegationRewardOwner  *Owner                    `json:"delegationRewardOwner,omitempty"`
	PotentialReward        *json.Uint64              `json:"potentialReward,omitempty"`
	AccruedDelegateeReward *json.Uint64              `json:"accruedDelegateeReward,omitempty"`
	DelegationFee          json.Float32              `json:"delegationFee"`
	ExactDelegationFee     *json.Uint32              `json:"exactDelegationFee,omitempty"`
	Uptime                 *json.Float32             `json:"uptime,omitempty"`
	Connected              *bool                     `json:"connected,omitempty"`
	Staked                 []UTXO                    `json:"staked,omitempty"`
	Signer                 *signer.ProofOfPossession `json:"signer,omitempty"`

	// The delegators delegating to this validator
	DelegatorCount  *json.Uint64        `json:"delegatorCount,omitempty"`
	DelegatorWeight *json.Uint64        `json:"delegatorWeight,omitempty"`
	Delegators      *[]PrimaryDelegator `json:"delegators,omitempty"`
}

// GenesisPermissionlessValidator should be used for genesis validators only.
type GenesisPermissionlessValidator struct {
	GenesisValidator
	RewardOwner        *Owner                    `json:"rewardOwner,omitempty"`
	DelegationFee      json.Float32              `json:"delegationFee"`
	ExactDelegationFee *json.Uint32              `json:"exactDelegationFee,omitempty"`
	Staked             []UTXO                    `json:"staked,omitempty"`
	Signer             *signer.ProofOfPossession `json:"signer,omitempty"`
}

// PermissionedValidator is the repr. of a permissioned validator sent over APIs.
type PermissionedValidator struct {
	Staker
	// The owner the staking reward, if applicable, will go to
	Connected bool          `json:"connected"`
	Uptime    *json.Float32 `json:"uptime,omitempty"`
}

// PrimaryDelegator is the repr. of a primary network delegator sent over APIs.
type PrimaryDelegator struct {
	Staker
	RewardOwner     *Owner       `json:"rewardOwner,omitempty"`
	PotentialReward *json.Uint64 `json:"potentialReward,omitempty"`
}
