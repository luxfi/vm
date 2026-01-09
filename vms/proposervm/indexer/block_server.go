// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package indexer

import (
	"context"

	chainblock "github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
)

// BlockServer represents all requests heightIndexer can issue
// against ProposerVM. All methods must be thread-safe.
type BlockServer interface {
	versiondb.Commitable

	// Note: this is a contention heavy call that should be avoided
	// for frequent/repeated indexer ops
	GetFullPostForkBlock(ctx context.Context, blkID ids.ID) (chainblock.Block, error)
}
