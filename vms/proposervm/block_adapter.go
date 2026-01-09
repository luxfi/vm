// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package proposervm

import (
	"context"

	"github.com/luxfi/consensus/engine/chain/block"
)

// blockAdapter adapts a proposervm Block to implement the engine/chain/block.Block interface
type blockAdapter struct {
	Block // proposervm Block interface
}

func (ba *blockAdapter) Status() uint8 {
	// Return the uint8 status directly from proposervm Block
	return ba.Block.Status()
}

// reverseBlockAdapter adapts an engine/chain/block.Block to implement the protocol/chain.Block interface
type reverseBlockAdapter struct {
	block.Block // engine/chain/block.Block interface
}

func (rba *reverseBlockAdapter) Status() uint8 {
	// Return the uint8 status directly from engine block
	return rba.Block.Status()
}

// Options implements the OracleBlock interface if the underlying block does
func (rba *reverseBlockAdapter) Options(ctx context.Context) ([2]block.Block, error) {
	type oracleBlock interface {
		Options(context.Context) ([2]block.Block, error)
	}

	oracleBlk, ok := rba.Block.(oracleBlock)
	if !ok {
		return [2]block.Block{}, errNotOracle
	}
	return oracleBlk.Options(ctx)
}
