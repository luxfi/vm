// Package lux provides compatibility with old import path.
// Deprecated: Use github.com/luxfi/utxo instead.
package lux

import "github.com/luxfi/utxo"

// Re-export types from github.com/luxfi/utxo
type (
	Asset              = utxo.Asset
	BaseTx             = utxo.BaseTx
	FlowChecker        = utxo.FlowChecker
	Metadata           = utxo.Metadata
	TransferableInput  = utxo.TransferableInput
	TransferableOutput = utxo.TransferableOutput
	UTXO               = utxo.UTXO
	UTXOID             = utxo.UTXOID
)

// Re-export functions
var (
	SortTransferableOutputs          = utxo.SortTransferableOutputs
	SortTransferableInputsWithSigners = utxo.SortTransferableInputsWithSigners
)
