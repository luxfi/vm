// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chains

import (
	"fmt"
	"sync"

	"github.com/luxfi/database"
	"github.com/luxfi/database/prefixdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// ChainDBManager manages chain database access using a single global BadgerDB.
// All chains share one BadgerDB instance with prefix-based isolation:
// 1. Single database - easier to manage, backup, and query across chains
// 2. Prefix isolation - each chain's data is prefixed by its chainID
// 3. G-Chain compatible - dgraph can index the entire database for GraphQL queries
type ChainDBManager struct {
	mu sync.RWMutex

	// Global shared database (BadgerDB)
	db database.Database

	// Cached prefixed databases per chain
	chainDBs map[ids.ID]database.Database

	log log.Logger
}

// ChainDBManagerConfig holds configuration for the chain database manager
type ChainDBManagerConfig struct {
	// DB is the global shared database (BadgerDB)
	DB database.Database

	Log log.Logger
}

// NewChainDBManager creates a new chain database manager using a single global BadgerDB
func NewChainDBManager(config ChainDBManagerConfig) *ChainDBManager {
	return &ChainDBManager{
		db:       config.DB,
		chainDBs: make(map[ids.ID]database.Database),
		log:      config.Log,
	}
}

// GetDatabase returns a prefixed database for the given chain.
// Uses prefix-based isolation on the single global BadgerDB.
func (m *ChainDBManager) GetDatabase(chainID ids.ID, chainAlias string) (database.Database, error) {
	if m.db == nil {
		return nil, fmt.Errorf("global database not initialized")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check cache first
	if db, exists := m.chainDBs[chainID]; exists {
		return db, nil
	}

	// Create prefixed database for this chain
	chainDB := prefixdb.New(chainID[:], m.db)
	m.chainDBs[chainID] = chainDB

	if m.log != nil {
		m.log.Info("Created prefixed database for chain",
			log.Stringer("chainID", chainID),
			log.String("alias", chainAlias),
		)
	}

	return chainDB, nil
}

// GetVMDatabase returns a VM-prefixed database for the given chain.
// Adds a "vm" prefix within the chain's prefix for VM-specific data.
func (m *ChainDBManager) GetVMDatabase(chainID ids.ID, chainAlias string) (database.Database, error) {
	chainDB, err := m.GetDatabase(chainID, chainAlias)
	if err != nil {
		return nil, err
	}

	// Add VM prefix to isolate VM data from other chain data
	return prefixdb.New(VMDBPrefix, chainDB), nil
}

// GetGlobalDB returns the underlying global database.
// This is useful for G-Chain (dgraph-powered GraphQL VM) to query across all chains.
func (m *ChainDBManager) GetGlobalDB() database.Database {
	return m.db
}

// Close is a no-op since the global database lifecycle is managed elsewhere.
// Chain-specific prefixed databases don't need to be closed separately.
func (m *ChainDBManager) Close() error {
	// Clear cache
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chainDBs = make(map[ids.ID]database.Database)
	return nil
}

// GetAllChainIDs returns all chain IDs that have databases allocated.
// Useful for G-Chain to enumerate chains for indexing.
func (m *ChainDBManager) GetAllChainIDs() []ids.ID {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]ids.ID, 0, len(m.chainDBs))
	for id := range m.chainDBs {
		result = append(result, id)
	}
	return result
}

// GetDatabasePrefix returns the prefix used for a chain's data.
// This is the chainID bytes, which can be used by G-Chain to iterate chain data.
func (m *ChainDBManager) GetDatabasePrefix(chainID ids.ID) []byte {
	return chainID[:]
}
