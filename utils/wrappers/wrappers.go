// Package wrappers provides compatibility with old import path.
// Deprecated: Use github.com/luxfi/util/wrappers instead.
package wrappers

import "github.com/luxfi/util/wrappers"

// Re-export types from github.com/luxfi/util/wrappers
type (
	Errs   = wrappers.Errs
	Packer = wrappers.Packer
	Closer = wrappers.Closer
)
