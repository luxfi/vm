// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package state

import (
	"github.com/luxfi/metric"

	"github.com/luxfi/database/prefixdb"
	"github.com/luxfi/database/versiondb"
)

var (
	chainStatePrefix  = []byte("chain")
	blockStatePrefix  = []byte("block")
	heightIndexPrefix = []byte("height")
)

type State interface {
	ChainState
	BlockState
	HeightIndex

	// Commit writes all pending changes to the underlying database.
	Commit() error
}

type state struct {
	ChainState
	BlockState
	HeightIndex
}

func New(db *versiondb.Database) State {
	chainDB := prefixdb.New(chainStatePrefix, db)
	blockDB := prefixdb.New(blockStatePrefix, db)
	heightDB := prefixdb.New(heightIndexPrefix, db)

	return &state{
		ChainState:  NewChainState(chainDB),
		BlockState:  NewBlockState(blockDB),
		HeightIndex: NewHeightIndex(heightDB, db),
	}
}

func NewMetered(db *versiondb.Database, namespace string, metrics metric.Registerer) (State, error) {
	chainDB := prefixdb.New(chainStatePrefix, db)
	blockDB := prefixdb.New(blockStatePrefix, db)
	heightDB := prefixdb.New(heightIndexPrefix, db)

	blockState, err := NewMeteredBlockState(blockDB, namespace, metrics)
	if err != nil {
		return nil, err
	}

	return &state{
		ChainState:  NewChainState(chainDB),
		BlockState:  blockState,
		HeightIndex: NewHeightIndex(heightDB, db),
	}, nil
}

// Since HeightIndex embeds versiondb.Commitable, the Commit method
// is already available through the embedded HeightIndex interface.
