// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fee

type StaticConfig struct {
	// Fee that is burned by every non-state creating transaction
	TxFee uint64 `json:"txFee"`

	// Fee that must be burned by every state creating transaction before AP3
	CreateAssetTxFee uint64 `json:"createAssetTxFee"`

	// Fee that must be burned by every network creating transaction after AP3
	CreateNetworkTxFee uint64 `json:"createNetworkTxFee"`

	// Fee that must be burned by every transform chain transaction
	TransformChainTxFee uint64 `json:"transformChainTxFee"`

	// Fee that must be burned by every chain creating transaction after AP3
	CreateChainTxFee uint64 `json:"createChainTxFee"`

	// Transaction fee for adding a primary network validator
	AddPrimaryNetworkValidatorFee uint64 `json:"addPrimaryNetworkValidatorFee"`

	// Transaction fee for adding a primary network delegator
	AddPrimaryNetworkDelegatorFee uint64 `json:"addPrimaryNetworkDelegatorFee"`

	// Transaction fee for adding a chain validator
	AddChainValidatorFee uint64 `json:"addChainValidatorFee"`

	// Transaction fee for adding a chain delegator
	AddChainDelegatorFee uint64 `json:"addChainDelegatorFee"`
}
