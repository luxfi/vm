// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import "github.com/luxfi/consensus/engine/chain/block"

// MessageType is an alias for block.MessageType for compatibility.
type MessageType = block.MessageType

// Re-export message type constants from block package.
const (
	PendingTxs    = block.PendingTxs
	StateSyncDone = block.StateSyncDone
)
