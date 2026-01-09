// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package platformvm

import (
	stdjson "encoding/json"
	"time"

	avajson "github.com/luxfi/codec"
	validators "github.com/luxfi/consensus/validator"
	"github.com/luxfi/constantsants"
	"github.com/luxfi/formatting"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/api"
	"github.com/luxfi/vm/utils/json"
	"github.com/luxfi/vm/vms/components/gas"
	"github.com/luxfi/vm/vms/components/lux"
	platformapi "github.com/luxfi/vm/vms/platformvm/api"
	"github.com/luxfi/vm/vms/platformvm/status"
	"github.com/luxfi/vm/vms/types"
)

type GetBalanceRequest struct {
	Addresses []string `json:"addresses"`
}

// Note: We explicitly duplicate LUX out of the maps to ensure backwards
// compatibility.
type GetBalanceResponse struct {
	// Balance, in nLUX, of the address
	Balance             json.Uint64            `json:"balance"`
	Unlocked            json.Uint64            `json:"unlocked"`
	LockedStakeable     json.Uint64            `json:"lockedStakeable"`
	LockedNotStakeable  json.Uint64            `json:"lockedNotStakeable"`
	Balances            map[ids.ID]json.Uint64 `json:"balances"`
	Unlockeds           map[ids.ID]json.Uint64 `json:"unlockeds"`
	LockedStakeables    map[ids.ID]json.Uint64 `json:"lockedStakeables"`
	LockedNotStakeables map[ids.ID]json.Uint64 `json:"lockedNotStakeables"`
	UTXOIDs             []*lux.UTXOID          `json:"utxoIDs"`
}

// GetNetArgs are the arguments to GetNet
type GetNetArgs struct {
	// ID of the net to retrieve information about
	NetID ids.ID `json:"netID"`
}

// GetNetResponse is the response from calling GetNet
type GetNetResponse struct {
	// whether it is permissioned or not
	IsPermissioned bool `json:"isPermissioned"`
	// net auth information for a permissioned net
	ControlKeys []string    `json:"controlKeys"`
	Threshold   json.Uint32 `json:"threshold"`
	Locktime    json.Uint64 `json:"locktime"`
	// net transformation tx ID for an elastic net
	NetTransformationTxID ids.ID `json:"netTransformationTxID"`
	// net conversion information for an L1
	ConversionID   ids.ID              `json:"conversionID"`
	ManagerChainID ids.ID              `json:"managerChainID"`
	ManagerAddress types.JSONByteSlice `json:"managerAddress"`
}

// APINet is a representation of a net used in API calls
type APINet struct {
	// ID of the net
	ID ids.ID `json:"id"`

	// Each element of [ControlKeys] the address of a public key.
	// A transaction to add a validator to this net requires
	// signatures from [Threshold] of these keys to be valid.
	ControlKeys []string    `json:"controlKeys"`
	Threshold   json.Uint32 `json:"threshold"`
}

// GetNetsArgs are the arguments to GetNets
type GetNetsArgs struct {
	// IDs of the nets to retrieve information about
	// If omitted, gets all nets
	IDs []ids.ID `json:"ids"`
}

// GetNetsResponse is the response from calling GetNets
type GetNetsResponse struct {
	// Each element is a net that exists
	// Null if there are no nets other than the primary network
	Nets []APINet `json:"nets"`
}

// GetStakingAssetIDArgs are the arguments to GetStakingAssetID
type GetStakingAssetIDArgs struct {
	NetID ids.ID `json:"netID"`
}

// GetStakingAssetIDResponse is the response from calling GetStakingAssetID
type GetStakingAssetIDResponse struct {
	AssetID ids.ID `json:"assetID"`
}

// APIBlockchain is the representation of a blockchain used in API calls
type APIBlockchain struct {
	// Blockchain's ID
	ID ids.ID `json:"id"`

	// Blockchain's (non-unique) human-readable name
	Name string `json:"name"`

	// Net that validates the blockchain
	NetID ids.ID `json:"netID"`

	// Virtual Machine the blockchain runs
	VMID ids.ID `json:"vmID"`
}

// GetBlockchainsResponse is the response from a call to GetBlockchains
type GetBlockchainsResponse struct {
	// blockchains that exist
	Blockchains []APIBlockchain `json:"blockchains"`
}

type GetTxStatusArgs struct {
	TxID ids.ID `json:"txID"`
}

type GetTxStatusResponse struct {
	Status status.Status `json:"status"`
	// Reason this tx was dropped.
	// Only non-empty if Status is dropped
	Reason string `json:"reason,omitempty"`
}

// PrimaryNetworkID is re-exported for callers that expect it here.
var PrimaryNetworkID = constants.PrimaryNetworkID

// GetCurrentValidatorsArgs are the arguments for calling GetCurrentValidators.
type GetCurrentValidatorsArgs struct {
	// Net we're listing the validators of.
	// If omitted, defaults to primary network.
	NetID ids.ID `json:"netID"`
	// NodeIDs of validators to request. If [NodeIDs]
	// is empty, it fetches all current validators. If
	// some nodeIDs are not currently validators, they
	// will be omitted from the response.
	NodeIDs []ids.NodeID `json:"nodeIDs"`
}

// GetCurrentValidatorsReply are the results from calling GetCurrentValidators.
// Each validator contains a list of delegators to itself.
type GetCurrentValidatorsReply struct {
	Validators []any `json:"validators"`
}

// GetL1ValidatorArgs are the arguments for GetL1Validator.
type GetL1ValidatorArgs struct {
	ValidationID ids.ID `json:"validationID"`
}

// GetL1ValidatorReply is the response from GetL1Validator.
type GetL1ValidatorReply struct {
	platformapi.APIL1Validator
	NetID  ids.ID         `json:"netID"`
	Height avajson.Uint64 `json:"height"`
}

// GetCurrentSupplyArgs are the arguments for calling GetCurrentSupply.
type GetCurrentSupplyArgs struct {
	NetID ids.ID `json:"netID"`
}

// GetCurrentSupplyReply are the results from calling GetCurrentSupply.
type GetCurrentSupplyReply struct {
	Supply avajson.Uint64 `json:"supply"`
	Height avajson.Uint64 `json:"height"`
}

// SampleValidatorsArgs are the arguments for calling SampleValidators.
type SampleValidatorsArgs struct {
	// Number of validators in the sample.
	Size json.Uint16 `json:"size"`
	// ID of net to sample validators from. If omitted, defaults to the primary network.
	NetID ids.ID `json:"netID"`
}

// SampleValidatorsReply are the results from calling SampleValidators.
type SampleValidatorsReply struct {
	Validators []ids.NodeID `json:"validators"`
}

// GetBlockchainStatusArgs are the arguments for calling GetBlockchainStatus.
// BlockchainID is the ID of or an alias of the blockchain to get the status of.
type GetBlockchainStatusArgs struct {
	BlockchainID string `json:"blockchainID"`
}

// GetBlockchainStatusReply is the reply from calling GetBlockchainStatus.
// Status is the blockchain's status.
type GetBlockchainStatusReply struct {
	Status status.BlockchainStatus `json:"status"`
}

// ValidatedByArgs are the arguments for calling ValidatedBy.
type ValidatedByArgs struct {
	// ValidatedBy returns the ID of the net validating the blockchain with this ID.
	BlockchainID ids.ID `json:"blockchainID"`
}

// ValidatedByResponse is the reply from calling ValidatedBy.
type ValidatedByResponse struct {
	// ID of the net validating the specified blockchain.
	NetID ids.ID `json:"netID"`
}

// ValidatesArgs are the arguments to Validates.
type ValidatesArgs struct {
	NetID ids.ID `json:"netID"`
}

// ValidatesResponse is the response from calling Validates.
type ValidatesResponse struct {
	BlockchainIDs []ids.ID `json:"blockchainIDs"`
}

// GetStakeArgs are the arguments for calling GetStake.
type GetStakeArgs struct {
	api.JSONAddresses
	ValidatorsOnly bool                `json:"validatorsOnly"`
	Encoding       formatting.Encoding `json:"encoding"`
}

// GetStakeReply is the response from calling GetStake.
type GetStakeReply struct {
	Staked  json.Uint64            `json:"staked"`
	Stakeds map[ids.ID]json.Uint64 `json:"stakeds"`
	// String representation of staked outputs.
	Outputs []string `json:"stakedOutputs"`
	// Encoding of [Outputs].
	Encoding formatting.Encoding `json:"encoding"`
}

// GetMinStakeArgs are the arguments for calling GetMinStake.
type GetMinStakeArgs struct {
	NetID ids.ID `json:"netID"`
}

// GetMinStakeReply is the response from calling GetMinStake.
type GetMinStakeReply struct {
	MinValidatorStake json.Uint64 `json:"minValidatorStake"`
	MinDelegatorStake json.Uint64 `json:"minDelegatorStake"`
}

// GetTotalStakeArgs are the arguments for calling GetTotalStake.
type GetTotalStakeArgs struct {
	NetID ids.ID `json:"netID"`
}

// GetTotalStakeReply is the response from calling GetTotalStake.
type GetTotalStakeReply struct {
	// Deprecated: Use Weight instead.
	Stake  json.Uint64 `json:"stake"`
	Weight json.Uint64 `json:"weight"`
}

// GetRewardUTXOsReply defines the GetRewardUTXOs replies returned from the API.
type GetRewardUTXOsReply struct {
	NumFetched json.Uint64         `json:"numFetched"`
	UTXOs      []string            `json:"utxos"`
	Encoding   formatting.Encoding `json:"encoding"`
}

// GetTimestampReply is the response from GetTimestamp.
type GetTimestampReply struct {
	Timestamp time.Time `json:"timestamp"`
}

// GetValidatorsAtArgs are the arguments for GetValidatorsAt.
type GetValidatorsAtArgs struct {
	Height platformapi.Height `json:"height"`
	NetID  ids.ID             `json:"netID"`
}

type jsonGetValidatorOutput struct {
	PublicKey *string     `json:"publicKey"`
	Weight    json.Uint64 `json:"weight"`
}

func (v *GetValidatorsAtReply) MarshalJSON() ([]byte, error) {
	m := make(map[ids.NodeID]*jsonGetValidatorOutput, len(v.Validators))
	for _, vdr := range v.Validators {
		vdrJSON := &jsonGetValidatorOutput{
			Weight: json.Uint64(vdr.Weight),
		}

		if vdr.PublicKey != nil {
			pk, err := formatting.Encode(formatting.HexNC, vdr.PublicKey)
			if err != nil {
				return nil, err
			}
			vdrJSON.PublicKey = &pk
		}

		m[vdr.NodeID] = vdrJSON
	}
	return stdjson.Marshal(m)
}

func (v *GetValidatorsAtReply) UnmarshalJSON(b []byte) error {
	var m map[ids.NodeID]*jsonGetValidatorOutput
	if err := stdjson.Unmarshal(b, &m); err != nil {
		return err
	}

	if m == nil {
		v.Validators = nil
		return nil
	}

	v.Validators = make(map[ids.NodeID]*validators.GetValidatorOutput, len(m))
	for nodeID, vdrJSON := range m {
		vdr := &validators.GetValidatorOutput{
			NodeID: nodeID,
			Weight: uint64(vdrJSON.Weight),
		}

		if vdrJSON.PublicKey != nil {
			pkBytes, err := formatting.Decode(formatting.HexNC, *vdrJSON.PublicKey)
			if err != nil {
				return err
			}
			vdr.PublicKey = pkBytes
		}

		v.Validators[nodeID] = vdr
	}
	return nil
}

// GetValidatorsAtReply is the response from GetValidatorsAt.
type GetValidatorsAtReply struct {
	Validators map[ids.NodeID]*validators.GetValidatorOutput
}

// GetFeeStateReply is the response from GetFeeState.
type GetFeeStateReply struct {
	gas.State
	Price gas.Price `json:"price"`
	Time  time.Time `json:"timestamp"`
}

// GetValidatorFeeStateReply is the response from GetValidatorFeeState.
type GetValidatorFeeStateReply struct {
	Excess gas.Gas   `json:"excess"`
	Price  gas.Price `json:"price"`
	Time   time.Time `json:"timestamp"`
}
