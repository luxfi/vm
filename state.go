// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

// State is the high-level lifecycle state of a VM instance.
type State uint8

const (
	// Unknown is the default / unset state.
	Unknown State = iota

	// Starting indicates the VM process is up, but not ready to serve.
	Starting

	// Syncing indicates the VM is downloading/applying state to reach tip.
	Syncing

	// Bootstrapping indicates the VM is performing consensus bootstrap
	// (e.g., fetching/accepting frontier, validating, etc.).
	Bootstrapping

	// Ready indicates the VM is fully operational and serving normally.
	Ready

	// Degraded indicates the VM is running but not healthy (e.g., stalled,
	// persistent errors, partial service).
	Degraded

	// Stopping indicates shutdown has been requested and is in progress.
	Stopping

	// Stopped indicates the VM is not running.
	Stopped
)

// String returns the string representation of the state
func (s State) String() string {
	switch s {
	case Unknown:
		return "Unknown"
	case Starting:
		return "Starting"
	case Syncing:
		return "Syncing"
	case Bootstrapping:
		return "Bootstrapping"
	case Ready:
		return "Ready"
	case Degraded:
		return "Degraded"
	case Stopping:
		return "Stopping"
	case Stopped:
		return "Stopped"
	default:
		return "Unknown"
	}
}
