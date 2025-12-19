// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

// State is the high-level lifecycle state of a VM instance.
type State uint8

const (
	// Unknown is the default / unset state.
	Unknown State = iota

	// Syncing indicates the VM is downloading/applying state to reach tip.
	Syncing

	// Bootstrapping indicates the VM is performing consensus bootstrap.
	Bootstrapping

	// NormalOp indicates the VM is fully operational and serving normally.
	NormalOp
)

// String returns the string representation of the state
func (s State) String() string {
	switch s {
	case Unknown:
		return "Unknown"
	case Syncing:
		return "Syncing"
	case Bootstrapping:
		return "Bootstrapping"
	case NormalOp:
		return "NormalOp"
	default:
		return "Unknown"
	}
}
