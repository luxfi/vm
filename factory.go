// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import (
	"github.com/luxfi/log"
)

// Factory creates new VM instances.
// A Factory creates new instances of a VM
type Factory interface {
	// New creates a new VM instance with the given logger.
	New(log.Logger) (interface{}, error)
}
