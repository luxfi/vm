// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package dag provides RPC infrastructure for DAG-based VMs (DAGVM).
// This implements the server and client for VMs that use vertices with multiple parents.
package dag

import (
	"context"

	"github.com/luxfi/consensus/core/choices"
	dagvertex "github.com/luxfi/consensus/engine/dag/vertex"
	"github.com/luxfi/ids"
)

// Vertex represents a vertex in the DAG with multiple parent references.
// Unlike blocks (single parent), vertices can reference multiple parents,
// enabling parallel transaction processing.
type Vertex interface {
	// ID returns the unique identifier of this vertex
	ID() ids.ID
	// Bytes returns the serialized form of this vertex
	Bytes() []byte
	// Height returns the height of this vertex in the DAG
	Height() uint64
	// Epoch returns the epoch this vertex belongs to
	Epoch() uint32
	// Parents returns the IDs of all parent vertices (can be multiple)
	Parents() []ids.ID
	// Txs returns the transaction IDs contained in this vertex
	Txs() []ids.ID
	// Status returns the consensus status of this vertex
	Status() choices.Status
	// Accept marks this vertex as accepted
	Accept(context.Context) error
	// Reject marks this vertex as rejected
	Reject(context.Context) error
	// Verify verifies this vertex
	Verify(context.Context) error
}

// DAGVM represents a DAG-based virtual machine.
// Unlike ChainVM which uses linear blocks, DAGVM uses a directed acyclic graph
// structure that allows for parallel transaction processing.
type DAGVM interface {
	// Initialize initializes the VM with the provided context and configuration
	Initialize(
		ctx context.Context,
		vmCtx interface{},
		db interface{},
		genesisBytes []byte,
		upgradeBytes []byte,
		configBytes []byte,
		msgChan interface{},
		fxs []interface{},
		appSender interface{},
	) error

	// ParseVertex parses a vertex from bytes
	ParseVertex(ctx context.Context, bytes []byte) (Vertex, error)

	// BuildVertex creates a new vertex from pending transactions
	BuildVertex(ctx context.Context) (Vertex, error)

	// GetVertex retrieves a vertex by ID
	GetVertex(ctx context.Context, id ids.ID) (Vertex, error)

	// SetPreference sets the preferred vertex
	SetPreference(ctx context.Context, id ids.ID) error

	// LastAccepted returns the ID of the last accepted vertex
	LastAccepted(ctx context.Context) (ids.ID, error)

	// Shutdown gracefully shuts down the VM
	Shutdown(ctx context.Context) error

	// SetState sets the operational state of the VM
	SetState(ctx context.Context, state uint32) error

	// Version returns the VM's version string
	Version(ctx context.Context) (string, error)

	// HealthCheck returns the VM's health status
	HealthCheck(ctx context.Context) (interface{}, error)

	// Connected is called when a node connects
	Connected(ctx context.Context, nodeID ids.NodeID, version interface{}) error

	// Disconnected is called when a node disconnects
	Disconnected(ctx context.Context, nodeID ids.NodeID) error

	// WaitForEvent blocks until the next event (e.g., pending txs) is available
	WaitForEvent(ctx context.Context) (interface{}, error)
}

// vertexWrapper wraps a consensus vertex to implement our Vertex interface
type vertexWrapper struct {
	dagvertex.Vertex
}

// Ensure vertexWrapper implements Vertex
var _ Vertex = (*vertexWrapper)(nil)

// WrapVertex wraps a consensus vertex
func WrapVertex(v dagvertex.Vertex) Vertex {
	if v == nil {
		return nil
	}
	return &vertexWrapper{Vertex: v}
}

// UnwrapVertex unwraps a vertex to the consensus type
func UnwrapVertex(v Vertex) dagvertex.Vertex {
	if vw, ok := v.(*vertexWrapper); ok {
		return vw.Vertex
	}
	return nil
}
