// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zvm

import (
	"encoding/binary"
	"errors"
	"sync"

	"github.com/luxfi/log"

	"github.com/luxfi/database"
)

const (
	// Database prefixes
	nullifierPrefix    = 0x20
	nullifierCountKey  = "nullifier_count"
	nullifierHeightKey = "nullifier_height_"
)

// NullifierDB manages spent nullifiers
type NullifierDB struct {
	db  database.Database
	log log.Logger

	// Caches
	nullifierCache map[string]uint64 // nullifier -> height when spent
	nullifierCount uint64

	// Indexes
	heightIndex map[uint64][]string // height -> nullifiers

	mu sync.RWMutex
}

// NewNullifierDB creates a new nullifier database
func NewNullifierDB(db database.Database, log log.Logger) (*NullifierDB, error) {
	ndb := &NullifierDB{
		db:             db,
		log:            log,
		nullifierCache: make(map[string]uint64),
		heightIndex:    make(map[uint64][]string),
	}

	// Load nullifier count
	countBytes, err := db.Get([]byte(nullifierCountKey))
	if err == database.ErrNotFound {
		ndb.nullifierCount = 0
	} else if err != nil {
		return nil, err
	} else {
		ndb.nullifierCount = binary.BigEndian.Uint64(countBytes)
	}

	// Load nullifiers from DB (in production, this would be more sophisticated)
	if err := ndb.loadNullifiers(); err != nil {
		return nil, err
	}

	return ndb, nil
}

// MarkNullifierSpent marks a nullifier as spent
func (ndb *NullifierDB) MarkNullifierSpent(nullifier []byte, height uint64) error {
	ndb.mu.Lock()
	defer ndb.mu.Unlock()

	nullifierStr := string(nullifier)

	// Check if already spent
	if _, exists := ndb.nullifierCache[nullifierStr]; exists {
		return errors.New("nullifier already spent")
	}

	// Store in database
	key := makeNullifierKey(nullifier)
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, height)

	if err := ndb.db.Put(key, heightBytes); err != nil {
		return err
	}

	// Update cache
	ndb.nullifierCache[nullifierStr] = height

	// Update height index
	ndb.heightIndex[height] = append(ndb.heightIndex[height], nullifierStr)

	// Update count
	ndb.nullifierCount++
	countBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(countBytes, ndb.nullifierCount)
	if err := ndb.db.Put([]byte(nullifierCountKey), countBytes); err != nil {
		return err
	}

	ndb.log.Debug("Marked nullifier as spent",
		log.Uint64("height", height),
		log.Uint64("nullifierCount", ndb.nullifierCount),
	)

	return nil
}

// IsNullifierSpent checks if a nullifier has been spent
func (ndb *NullifierDB) IsNullifierSpent(nullifier []byte) bool {
	ndb.mu.RLock()
	defer ndb.mu.RUnlock()

	nullifierStr := string(nullifier)

	// Check cache
	if _, exists := ndb.nullifierCache[nullifierStr]; exists {
		return true
	}

	// Check database
	key := makeNullifierKey(nullifier)
	_, err := ndb.db.Get(key)
	return err == nil
}

// GetNullifierHeight returns the height when a nullifier was spent
func (ndb *NullifierDB) GetNullifierHeight(nullifier []byte) (uint64, error) {
	ndb.mu.RLock()
	defer ndb.mu.RUnlock()

	nullifierStr := string(nullifier)

	// Check cache
	if height, exists := ndb.nullifierCache[nullifierStr]; exists {
		return height, nil
	}

	// Load from database
	key := makeNullifierKey(nullifier)
	heightBytes, err := ndb.db.Get(key)
	if err != nil {
		return 0, errors.New("nullifier not found")
	}

	height := binary.BigEndian.Uint64(heightBytes)

	// Update cache
	ndb.nullifierCache[nullifierStr] = height

	return height, nil
}

// GetNullifiersByHeight returns all nullifiers spent at a specific height
func (ndb *NullifierDB) GetNullifiersByHeight(height uint64) [][]byte {
	ndb.mu.RLock()
	defer ndb.mu.RUnlock()

	nullifierStrs, exists := ndb.heightIndex[height]
	if !exists {
		return nil
	}

	nullifiers := make([][]byte, len(nullifierStrs))
	for i, nullifierStr := range nullifierStrs {
		nullifiers[i] = []byte(nullifierStr)
	}

	return nullifiers
}

// GetNullifierCount returns the total number of spent nullifiers
func (ndb *NullifierDB) GetNullifierCount() uint64 {
	ndb.mu.RLock()
	defer ndb.mu.RUnlock()
	return ndb.nullifierCount
}

// RemoveNullifier removes a nullifier (used for reorg)
func (ndb *NullifierDB) RemoveNullifier(nullifier []byte) error {
	ndb.mu.Lock()
	defer ndb.mu.Unlock()

	nullifierStr := string(nullifier)

	// Get height from cache
	height, exists := ndb.nullifierCache[nullifierStr]
	if !exists {
		// Try loading from DB
		key := makeNullifierKey(nullifier)
		heightBytes, err := ndb.db.Get(key)
		if err != nil {
			return errors.New("nullifier not found")
		}
		height = binary.BigEndian.Uint64(heightBytes)
	}

	// Remove from database
	key := makeNullifierKey(nullifier)
	if err := ndb.db.Delete(key); err != nil {
		return err
	}

	// Remove from cache
	delete(ndb.nullifierCache, nullifierStr)

	// Update height index
	if heightNullifiers, exists := ndb.heightIndex[height]; exists {
		for i, n := range heightNullifiers {
			if n == nullifierStr {
				ndb.heightIndex[height] = append(heightNullifiers[:i], heightNullifiers[i+1:]...)
				break
			}
		}
	}

	// Update count
	ndb.nullifierCount--
	countBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(countBytes, ndb.nullifierCount)
	if err := ndb.db.Put([]byte(nullifierCountKey), countBytes); err != nil {
		return err
	}

	return nil
}

// PruneOldNullifiers removes nullifiers older than a certain height
func (ndb *NullifierDB) PruneOldNullifiers(minHeight uint64) error {
	ndb.mu.Lock()
	defer ndb.mu.Unlock()

	pruneCount := 0

	// Find heights to prune
	var heightsToPrune []uint64
	for height := range ndb.heightIndex {
		if height < minHeight {
			heightsToPrune = append(heightsToPrune, height)
		}
	}

	// Prune nullifiers at each height
	for _, height := range heightsToPrune {
		nullifierStrs := ndb.heightIndex[height]
		for _, nullifierStr := range nullifierStrs {
			nullifier := []byte(nullifierStr)

			// Remove from database
			key := makeNullifierKey(nullifier)
			if err := ndb.db.Delete(key); err != nil {
				ndb.log.Warn("Failed to prune nullifier", log.Reflect("error", err))
				continue
			}

			// Remove from cache
			delete(ndb.nullifierCache, nullifierStr)
			pruneCount++
		}

		// Remove height index
		delete(ndb.heightIndex, height)
	}

	// Update count
	ndb.nullifierCount -= uint64(pruneCount)
	countBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(countBytes, ndb.nullifierCount)
	if err := ndb.db.Put([]byte(nullifierCountKey), countBytes); err != nil {
		return err
	}

	ndb.log.Info("Pruned old nullifiers",
		log.Int("pruneCount", pruneCount),
		log.Uint64("minHeight", minHeight),
		log.Uint64("remainingNullifiers", ndb.nullifierCount),
	)

	return nil
}

// loadNullifiers loads nullifiers from database to cache
func (ndb *NullifierDB) loadNullifiers() error {
	// In production, we would iterate through the DB
	// For now, we start with empty nullifier set
	return nil
}

// makeNullifierKey creates a database key for a nullifier
func makeNullifierKey(nullifier []byte) []byte {
	key := make([]byte, 1+len(nullifier))
	key[0] = nullifierPrefix
	copy(key[1:], nullifier)
	return key
}

// Close closes the nullifier database
func (ndb *NullifierDB) Close() {
	ndb.mu.Lock()
	defer ndb.mu.Unlock()

	ndb.nullifierCache = nil
	ndb.heightIndex = nil
}
