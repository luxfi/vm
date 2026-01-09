// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package state

// ReadOnlyChain provides read-only access to chain state
type ReadOnlyChain interface {
	// GetTimestamp returns the chain timestamp
	GetTimestamp() uint64
}
