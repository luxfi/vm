// Package wrappers provides compatibility with old import path.
// Deprecated: Use github.com/luxfi/utils/wrappers instead.
package wrappers

import "github.com/luxfi/utils/wrappers"

// Re-export types from github.com/luxfi/utils/wrappers
type (
	Errs   = wrappers.Errs
	Packer = wrappers.Packer
	Closer = wrappers.Closer
)
