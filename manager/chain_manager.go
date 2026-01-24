// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package manager

import "github.com/luxfi/ids"

// ChainManager provides chain lookup and aliasing for VM APIs.
// It is intentionally minimal and consensus-free.
type ChainManager interface {
	ids.Aliaser

	IsBootstrapped(ids.ID) bool
	RetryPendingChains(ids.ID) int
}

// TestChainManager implements ChainManager for tests.
var TestChainManager ChainManager = newTestChainManager()

type testChainManager struct {
	aliaser ids.Aliaser
}

func newTestChainManager() *testChainManager {
	return &testChainManager{aliaser: ids.NewAliaser()}
}

func (m *testChainManager) Lookup(alias string) (ids.ID, error) {
	return m.aliaser.Lookup(alias)
}

func (m *testChainManager) PrimaryAlias(id ids.ID) (string, error) {
	return m.aliaser.PrimaryAlias(id)
}

func (m *testChainManager) Aliases(id ids.ID) ([]string, error) {
	return m.aliaser.Aliases(id)
}

func (m *testChainManager) Alias(id ids.ID, alias string) error {
	return m.aliaser.Alias(id, alias)
}

func (m *testChainManager) RemoveAliases(id ids.ID) {
	m.aliaser.RemoveAliases(id)
}

func (m *testChainManager) PrimaryAliasOrDefault(id ids.ID) string {
	return m.aliaser.PrimaryAliasOrDefault(id)
}

func (*testChainManager) IsBootstrapped(ids.ID) bool {
	return false
}

func (*testChainManager) RetryPendingChains(ids.ID) int {
	return 0
}
