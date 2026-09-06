// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vms

import (
	"github.com/luxfi/vm/manager"
)

// Re-export types from manager package for backward compatibility.

// Factory creates new instances of a VM
type Factory = manager.Factory

// Manager tracks a collection of VM factories, their aliases, and their versions.
type Manager = manager.Manager

// ErrNotFound is returned when a VM factory is not found
var ErrNotFound = manager.ErrNotFound

// NewManager returns an instance of a VM manager
var NewManager = manager.NewManager
