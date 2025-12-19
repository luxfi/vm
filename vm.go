// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package vm defines virtual machine interfaces and types.
// This package provides the core abstractions for building VMs on Lux.
package vm

import (
	"context"

	"github.com/luxfi/ids"
)

// VM defines the interface for a virtual machine
type VM interface {
	// Initialize initializes the VM with the given configuration
	Initialize(context.Context, *Config) error

	// Shutdown cleanly stops the VM
	Shutdown(context.Context) error

	// Version returns the VM version
	Version(context.Context) (string, error)

	// SetState transitions the VM to the specified state
	SetState(context.Context, State) error
}

// Config defines VM configuration
type Config struct {
	ChainID   ids.ID
	NetworkID uint32
	NodeID    ids.NodeID
	PublicKey []byte
}
