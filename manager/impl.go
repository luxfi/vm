// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package manager

import (
	"context"
	"fmt"
	"sync"

	"github.com/luxfi/ids"
)

type manager struct {
	lock sync.RWMutex
	factories map[ids.ID]Factory
	aliases   map[ids.ID][]string
	lookup    map[string]ids.ID
}

func NewManager() Manager {
	return &manager{
		factories: make(map[ids.ID]Factory),
		aliases:   make(map[ids.ID][]string),
		lookup:    make(map[string]ids.ID),
	}
}

func (m *manager) RegisterFactory(ctx context.Context, vmID ids.ID, factory Factory) error {
	_ = ctx
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, exists := m.factories[vmID]; exists {
		return fmt.Errorf("factory %s already registered", vmID)
	}
	m.factories[vmID] = factory

	idAlias := vmID.String()
	m.lookup[idAlias] = vmID
	m.aliases[vmID] = []string{idAlias}
	return nil
}
func (m *manager) GetFactory(ctx context.Context, vmID ids.ID) (Factory, error) {
	_ = ctx
	m.lock.RLock()
	defer m.lock.RUnlock()

	factory, ok := m.factories[vmID]
	if !ok {
		return nil, ErrNotFound
	}
	return factory, nil
}
func (m *manager) ListFactories(ctx context.Context) ([]ids.ID, error) {
	_ = ctx
	m.lock.RLock()
	defer m.lock.RUnlock()

	vmIDs := make([]ids.ID, 0, len(m.factories))
	for vmID := range m.factories {
		vmIDs = append(vmIDs, vmID)
	}
	return vmIDs, nil
}

func (m *manager) Aliases(ctx context.Context, vmID ids.ID) ([]string, error) {
	_ = ctx
	m.lock.RLock()
	defer m.lock.RUnlock()

	aliases, ok := m.aliases[vmID]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]string(nil), aliases...), nil
}
func (m *manager) Alias(ctx context.Context, vmID ids.ID, alias string) error {
	_ = ctx
	m.lock.Lock()
	defer m.lock.Unlock()

	if existing, ok := m.lookup[alias]; ok && existing != vmID {
		return fmt.Errorf("alias %s already mapped to %s", alias, existing)
	}
	if _, ok := m.factories[vmID]; !ok {
		return ErrNotFound
	}
	m.lookup[alias] = vmID
	m.aliases[vmID] = append(m.aliases[vmID], alias)
	return nil
}
func (m *manager) PrimaryAlias(ctx context.Context, vmID ids.ID) (string, error) {
	_ = ctx
	m.lock.RLock()
	defer m.lock.RUnlock()

	aliases := m.aliases[vmID]
	if len(aliases) == 0 {
		return "", ErrNotFound
	}
	return aliases[0], nil
}
func (m *manager) Lookup(ctx context.Context, alias string) (ids.ID, error) {
	_ = ctx
	m.lock.RLock()
	defer m.lock.RUnlock()

	vmID, ok := m.lookup[alias]
	if !ok {
		return ids.Empty, ErrNotFound
	}
	return vmID, nil
}

func (m *manager) Versions(ctx context.Context) (map[string]string, error) {
	_ = ctx
	m.lock.RLock()
	defer m.lock.RUnlock()

	return map[string]string{}, nil
}
