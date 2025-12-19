// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import "github.com/luxfi/ids"

// Message signals from VM to consensus engine
type Message struct {
	Type    MessageType
	NodeID  ids.NodeID
	Content []byte
}

// MessageType identifies the message kind
type MessageType uint32

const (
	// PendingTxs indicates there are pending transactions to process
	PendingTxs MessageType = iota
	// StateSyncDone indicates state sync has completed
	StateSyncDone
)

// String returns the string representation of the message type
func (m MessageType) String() string {
	switch m {
	case PendingTxs:
		return "PendingTxs"
	case StateSyncDone:
		return "StateSyncDone"
	default:
		return "Unknown"
	}
}
