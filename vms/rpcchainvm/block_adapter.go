// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpcchainvm

import (
	consChain "github.com/luxfi/consensus/protocol/chain"
)

// blockChainAdapter wraps blockClient to provide uint8 Status() method for consChain.Block
type blockChainAdapter struct {
	*blockClient
}

// Status returns the block status as uint8
func (b *blockChainAdapter) Status() uint8 {
	return uint8(b.blockClient.Status())
}

// Ensure blockChainAdapter implements consChain.Block
var _ consChain.Block = (*blockChainAdapter)(nil)

// wrapBlockForChain converts a blockClient to have the correct Status() signature for consChain.Block
func wrapBlockForChain(bc *blockClient) consChain.Block {
	if bc == nil {
		return nil
	}
	return &blockChainAdapter{blockClient: bc}
}

// blockConsensusAdapter wraps blockClient for consensus interfaces
type blockConsensusAdapter struct {
	*blockClient
}

// Status returns the block status as uint8 for consensus
func (b *blockConsensusAdapter) Status() uint8 {
	return uint8(b.blockClient.Status())
}

// Ensure blockConsensusAdapter implements consensus consChain.Block
var _ consChain.Block = (*blockConsensusAdapter)(nil)

// wrapBlockForConsensus converts a blockClient for consensus interfaces
func wrapBlockForConsensus(bc *blockClient) consChain.Block {
	if bc == nil {
		return nil
	}
	return &blockConsensusAdapter{blockClient: bc}
}
