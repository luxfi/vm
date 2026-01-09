// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package exchangevm

import (
	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/formatting"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/api"
	"github.com/luxfi/vm/utils/json"
	"github.com/luxfi/vm/vms/components/lux"
)

// GetTxFeeReply is the response from a GetTxFee call
type GetTxFeeReply struct {
	TxFee            json.Uint64 `json:"txFee"`
	CreateAssetTxFee json.Uint64 `json:"createAssetTxFee"`
}

// FormattedAssetID defines a JSON formatted struct containing an assetID as a string
type FormattedAssetID struct {
	AssetID ids.ID `json:"assetID"`
}

// BuildGenesisArgs are arguments for BuildGenesis
type BuildGenesisArgs struct {
	NetworkID   json.Uint32                `json:"networkID"`
	GenesisData map[string]AssetDefinition `json:"genesisData"`
	Encoding    formatting.Encoding        `json:"encoding"`
}

type AssetDefinition struct {
	Name         string                   `json:"name"`
	Symbol       string                   `json:"symbol"`
	Denomination json.Uint8               `json:"denomination"`
	InitialState map[string][]interface{} `json:"initialState"`
	Memo         string                   `json:"memo"`
}

// BuildGenesisReply is the reply from BuildGenesis
type BuildGenesisReply struct {
	Bytes    string              `json:"bytes"`
	Encoding formatting.Encoding `json:"encoding"`
}

// GetTxStatusReply defines the GetTxStatus replies returned from the API
type GetTxStatusReply struct {
	Status choices.Status `json:"status"`
}

// GetAssetDescriptionArgs are arguments for passing into GetAssetDescription requests
type GetAssetDescriptionArgs struct {
	AssetID string `json:"assetID"`
}

// GetAssetDescriptionReply defines the GetAssetDescription replies returned from the API
type GetAssetDescriptionReply struct {
	FormattedAssetID
	Name         string     `json:"name"`
	Symbol       string     `json:"symbol"`
	Denomination json.Uint8 `json:"denomination"`
}

// GetBalanceArgs are arguments for passing into GetBalance requests
type GetBalanceArgs struct {
	Address        string `json:"address"`
	AssetID        string `json:"assetID"`
	IncludePartial bool   `json:"includePartial"`
}

// GetBalanceReply defines the GetBalance replies returned from the API
type GetBalanceReply struct {
	Balance json.Uint64  `json:"balance"`
	UTXOIDs []lux.UTXOID `json:"utxoIDs"`
}

type Balance struct {
	AssetID string      `json:"asset"`
	Balance json.Uint64 `json:"balance"`
}

type GetAllBalancesArgs struct {
	api.JSONAddress
	IncludePartial bool `json:"includePartial"`
}

// GetAllBalancesReply is the response from a call to GetAllBalances
type GetAllBalancesReply struct {
	Balances []Balance `json:"balances"`
}
