// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import "github.com/luxfi/ids"

// Fx is a feature extension for VMs
type Fx struct {
	ID ids.ID
	Fx interface{}
}

// FxLifecycle defines the lifecycle hooks for feature extensions
type FxLifecycle interface {
	// Initialize initializes the Fx with the parent VM
	Initialize(vm interface{}) error

	// Bootstrapping is called when the VM begins bootstrapping
	Bootstrapping() error

	// Bootstrapped is called when the VM finishes bootstrapping
	Bootstrapped() error
}
