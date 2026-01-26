// Package utils provides compatibility with old import path.
// Deprecated: Use github.com/luxfi/utils instead.
package utils

import "github.com/luxfi/utils"

// Re-export types and functions from github.com/luxfi/utils
type (
	Atomic[T any] = utils.Atomic[T]
	BytesPool     = utils.BytesPool
)

var (
	NewAtomic   = utils.NewAtomic[any]
	NewBytesPool = utils.NewBytesPool
	RandomBytes = utils.RandomBytes
	AppendSlices = utils.AppendSlices[any]
	Detach      = utils.Detach
	Err         = utils.Err
)
