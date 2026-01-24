// Package vm defines the minimal contract for a chain VM.
// This package is the only interface a chain VM must satisfy.
package vm

import (
	"context"

	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/ids"
)

// VM defines the minimal interface for a virtual machine.
type VM interface {
	Initialize(ctx context.Context, init Init) error
	Shutdown(ctx context.Context) error

	ParseBlock(ctx context.Context, b []byte) (Block, error)
	GetBlock(ctx context.Context, id ids.ID) (Block, error)

	SetPreference(ctx context.Context, id ids.ID) error
	LastAccepted(ctx context.Context) (ids.ID, error)
}

// Block defines the minimal interface for a block.
type Block interface {
	ID() ids.ID
	Parent() ids.ID
	Bytes() []byte
	Height() uint64
	Timestamp() int64
	Verify(context.Context) error
	Accept(context.Context) error
	Reject(context.Context) error
}

// Init is an alias for block.Init for compatibility.
// This ensures VMs using vm.Init are compatible with the consensus ChainVM interface.
type Init = block.Init

// Message is an alias for block.Message for compatibility.
type Message = block.Message
