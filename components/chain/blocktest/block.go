// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package blocktest

import (
	"context"
	"fmt"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/vm/components/state"
)

var (
	GenesisID        = ids.GenerateTestID()
	GenesisHeight    = uint64(0)
	GenesisTimestamp = time.Unix(1, 0)
	GenesisBytes     = []byte("genesis")

	nextID = uint64(1)
)

// Status constants
const (
	Unknown    uint8 = 0
	Processing uint8 = 1
	Rejected   uint8 = 2
	Accepted   uint8 = 3
)

// Block is a test block that implements block.Block
type Block struct {
	IDV        ids.ID
	HeightV    uint64
	TimestampV time.Time
	ParentV    ids.ID
	BytesV     []byte
	StatusV    uint8
	ErrV       error
	state      state.ReadOnlyChain
}

var Genesis = &Block{
	IDV:        GenesisID,
	HeightV:    GenesisHeight,
	TimestampV: GenesisTimestamp,
	ParentV:    ids.Empty,
	BytesV:     GenesisBytes,
	StatusV:    Accepted,
}

func (b *Block) ID() ids.ID {
	return b.IDV
}

func (b *Block) Height() uint64 {
	return b.HeightV
}

func (b *Block) Timestamp() time.Time {
	return b.TimestampV
}

func (b *Block) Parent() ids.ID {
	return b.ParentV
}

func (b *Block) ParentID() ids.ID {
	return b.ParentV
}

func (b *Block) Bytes() []byte {
	return b.BytesV
}

func (b *Block) Verify(context.Context) error {
	if b.ErrV != nil {
		return b.ErrV
	}
	return nil
}

func (b *Block) Status() uint8 {
	return b.StatusV
}

func (b *Block) Accept(context.Context) error {
	if b.ErrV != nil {
		return b.ErrV
	}
	b.StatusV = Accepted
	return nil
}

func (b *Block) Reject(context.Context) error {
	if b.ErrV != nil {
		return b.ErrV
	}
	b.StatusV = Rejected
	return nil
}

func (b *Block) State() state.ReadOnlyChain {
	return b.state
}

// BuildChild creates a child block of the given parent
func BuildChild(parent *Block) *Block {
	nextID++
	blockID := ids.ID{}
	copy(blockID[:], fmt.Sprintf("block_%d", nextID))

	timestamp := parent.Timestamp().Add(time.Second)

	return &Block{
		IDV:        blockID,
		HeightV:    parent.Height() + 1,
		TimestampV: timestamp,
		ParentV:    parent.ID(),
		BytesV:     []byte(fmt.Sprintf("block_%d", nextID)),
		StatusV:    Processing,
	}
}

// MakeLastAcceptedBlockF creates a LastAcceptedF function that returns the last block in the chain
func MakeLastAcceptedBlockF(blocks []*Block) func(context.Context) (ids.ID, error) {
	return func(context.Context) (ids.ID, error) {
		if len(blocks) == 0 {
			return ids.Empty, nil
		}
		return blocks[len(blocks)-1].ID(), nil
	}
}
