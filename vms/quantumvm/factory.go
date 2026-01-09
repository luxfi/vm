// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package qvm

import (
	"github.com/luxfi/log"
	"github.com/luxfi/vm/vms"
	"github.com/luxfi/vm/vms/quantumvm/config"
)

var _ vms.Factory = (*Factory)(nil)

// Factory implements vms.Factory interface for creating QVM instances
type Factory struct {
	config.Config
}

// New creates a new QVM instance
func (f *Factory) New(logger log.Logger) (interface{}, error) {
	// Validate configuration
	if err := f.Config.Validate(); err != nil {
		return nil, err
	}

	// Create and return new QVM instance
	vm := &VM{
		Config: f.Config,
		log:    logger,
	}

	return vm, nil
}
