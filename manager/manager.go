// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package manager

import (
	"context"
	"errors"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

var (
	ErrNotFound = errors.New("not found")
)

// Factory creates new instances of a VM
type Factory interface {
	New(log log.Logger) (interface{}, error)
}

// Manager tracks a collection of VM factories, their aliases, and their versions.
type Manager interface {
	// RegisterFactory registers a factory for a new VM type
	RegisterFactory(ctx context.Context, vmID ids.ID, factory Factory) error

	// GetFactory returns a factory for the given VM ID
	GetFactory(ctx context.Context, vmID ids.ID) (Factory, error)

	// ListFactories returns all registered VM factories
	ListFactories(ctx context.Context) ([]ids.ID, error)

	// Aliases returns all aliases for the given VM ID
	Aliases(ctx context.Context, vmID ids.ID) ([]string, error)

	// Alias registers an alias for a VM ID
	Alias(ctx context.Context, vmID ids.ID, alias string) error

	// PrimaryAlias returns the primary alias for a VM ID
	PrimaryAlias(ctx context.Context, vmID ids.ID) (string, error)

	// Lookup returns the VM ID for a given alias
	Lookup(ctx context.Context, alias string) (ids.ID, error)

	// Versions returns version strings keyed by VM alias or ID.
	Versions(ctx context.Context) (map[string]string, error)
}
