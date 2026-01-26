// Package secp256k1fx provides compatibility with old import path.
// Deprecated: Use github.com/luxfi/utxo/secp256k1fx instead.
package secp256k1fx

import "github.com/luxfi/utxo/secp256k1fx"

// Re-export types from github.com/luxfi/utxo/secp256k1fx
type (
	Credential      = secp256k1fx.Credential
	Factory         = secp256k1fx.Factory
	Fx              = secp256k1fx.Fx
	Input           = secp256k1fx.Input
	Keychain        = secp256k1fx.Keychain
	MintOperation   = secp256k1fx.MintOperation
	MintOutput      = secp256k1fx.MintOutput
	OutputOwners    = secp256k1fx.OutputOwners
	TransferInput   = secp256k1fx.TransferInput
	TransferOutput  = secp256k1fx.TransferOutput
	RecoverCache    = secp256k1fx.RecoverCache
	PublicKey       = secp256k1fx.PublicKey
)

// Re-export functions
var NewKeychain = secp256k1fx.NewKeychain
