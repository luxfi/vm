// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kmsvm

import (
	"github.com/luxfi/log"
	"github.com/luxfi/vm/vms"
	"github.com/luxfi/vm/vms/kmsvm/config"
)

var _ vms.Factory = (*Factory)(nil)

// Factory implements vms.Factory interface for creating K-Chain VM instances.
type Factory struct {
	config.Config
}

// New creates a new K-Chain VM instance.
func (f *Factory) New(logger log.Logger) (interface{}, error) {
	// Set default configuration if not provided
	if f.Config.ListenPort == 0 {
		f.Config = config.DefaultConfig()
	}

	// Validate configuration
	if err := f.Config.Validate(); err != nil {
		return nil, err
	}

	// Create and return new K-Chain VM instance
	vm := &VM{
		Config: f.Config,
		log:    logger,
	}

	return vm, nil
}

// NewFactory creates a new K-Chain VM factory with the given configuration.
func NewFactory(cfg config.Config) *Factory {
	return &Factory{Config: cfg}
}

// NewDefaultFactory creates a new K-Chain VM factory with default configuration.
func NewDefaultFactory() *Factory {
	return &Factory{Config: config.DefaultConfig()}
}
