// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package state

import (
	"errors"

	"github.com/luxfi/cache"
	"github.com/luxfi/cache/lru"
	"github.com/luxfi/cache/metercacher"
	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/constants"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/metric"
	"github.com/luxfi/vm/utils/wrappers"
	"github.com/luxfi/vm/vms/proposervm/block"
)

const blockCacheSize = 64 * constants.MiB

var (
	errBlockWrongVersion = errors.New("wrong version")

	_ BlockState = (*blockState)(nil)
)

type BlockState interface {
	GetBlock(blkID ids.ID) (block.Block, error)
	PutBlock(blk block.Block) error
	DeleteBlock(blkID ids.ID) error
}

type blockState struct {
	// Caches BlockID -> Block. If the Block is nil, that means the block is not
	// in storage.
	blkCache cache.Cacher[ids.ID, *blockWrapper]

	db database.Database
}

type blockWrapper struct {
	Block     []byte `serialize:"true"`
	StatusInt uint32 `serialize:"true"` // Store status as uint32 for serialization

	block  block.Block
	status choices.Status // Keep the actual status here
}

func cachedBlockSize(_ ids.ID, bw *blockWrapper) int {
	if bw == nil {
		return ids.IDLen + constants.PointerOverhead
	}
	return ids.IDLen + len(bw.Block) + wrappers.IntLen + 2*constants.PointerOverhead
}

func NewBlockState(db database.Database) BlockState {
	return &blockState{
		blkCache: lru.NewSizedCache(blockCacheSize, cachedBlockSize),
		db:       db,
	}
}

func NewMeteredBlockState(db database.Database, namespace string, metrics metric.Registerer) (BlockState, error) {
	registry, ok := metrics.(metric.Registry)
	if !ok {
		return nil, errors.New("metrics must be a Registry")
	}
	blkCache, err := metercacher.New[ids.ID, *blockWrapper](
		namespace,
		registry,
		lru.NewSizedCache(blockCacheSize, cachedBlockSize),
	)

	return &blockState{
		blkCache: blkCache,
		db:       db,
	}, err
}

func (s *blockState) GetBlock(blkID ids.ID) (block.Block, error) {
	if blk, found := s.blkCache.Get(blkID); found {
		if blk == nil {
			return nil, database.ErrNotFound
		}
		return blk.block, nil
	}

	blkWrapperBytes, err := s.db.Get(blkID[:])
	if err == database.ErrNotFound {
		s.blkCache.Put(blkID, nil)
		return nil, database.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	blkWrapper := blockWrapper{}
	parsedVersion, err := Codec.Unmarshal(blkWrapperBytes, &blkWrapper)
	if err != nil {
		return nil, err
	}
	if parsedVersion != CodecVersion {
		return nil, errBlockWrongVersion
	}

	// The key was in the database
	blk, err := block.ParseWithoutVerification(blkWrapper.Block)
	if err != nil {
		return nil, err
	}
	blkWrapper.block = blk
	blkWrapper.status = choices.Status(blkWrapper.StatusInt) // Convert back from uint32

	s.blkCache.Put(blkID, &blkWrapper)
	return blk, nil
}

func (s *blockState) PutBlock(blk block.Block) error {
	blkWrapper := blockWrapper{
		Block:  blk.Bytes(),
		status: choices.Accepted,
		block:  blk,
	}

	bytes, err := Codec.Marshal(CodecVersion, &blkWrapper)
	if err != nil {
		return err
	}

	blkID := blk.ID()
	s.blkCache.Put(blkID, &blkWrapper)
	return s.db.Put(blkID[:], bytes)
}

func (s *blockState) DeleteBlock(blkID ids.ID) error {
	s.blkCache.Evict(blkID)
	return s.db.Delete(blkID[:])
}
