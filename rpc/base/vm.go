// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package base provides the common RPC infrastructure for all VM shapes.
// This includes the shared operations that all VMs support regardless of
// whether they are chain-based (linear blocks), DAG-based (vertices), or
// other shapes.
package base

import (
	"context"
	"net/http"

	"github.com/luxfi/ids"
)

// VM defines the common interface that all VM shapes must implement.
// This is the base layer shared by ChainVM, DAGVM, and other shapes.
type VM interface {
	// Initialize initializes the VM with the provided context, database,
	// and configuration. The interface{} types allow flexibility for
	// shape-specific implementations.
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

	// Shutdown gracefully shuts down the VM
	Shutdown(context.Context) error

	// SetState sets the VM's operational state
	SetState(context.Context, State) error

	// Version returns the VM's version string
	Version(context.Context) (string, error)

	// Connected is called when a node connects
	Connected(ctx context.Context, nodeID ids.NodeID, version interface{}) error

	// Disconnected is called when a node disconnects
	Disconnected(ctx context.Context, nodeID ids.NodeID) error

	// HealthCheck returns the VM's health status
	HealthCheck(context.Context) (interface{}, error)

	// LastAccepted returns the ID of the last accepted block/vertex
	LastAccepted(context.Context) (ids.ID, error)
}

// State represents the operational state of a VM
type State uint32

const (
	// StateInitializing indicates the VM is initializing
	StateInitializing State = iota
	// StateStateSyncing indicates the VM is state syncing
	StateStateSyncing
	// StateBootstrapping indicates the VM is bootstrapping
	StateBootstrapping
	// StateNormalOp indicates the VM is in normal operation
	StateNormalOp
)

// HTTPHandler provides HTTP handler creation capability
type HTTPHandler interface {
	// NewHTTPHandler creates a new HTTP handler for the VM's API
	NewHTTPHandler(context.Context) (http.Handler, error)
}

// Gatherer provides metrics gathering capability
type Gatherer interface {
	// Gather returns the VM's metrics
	Gather() ([]*MetricFamily, error)
}

// MetricFamily represents a family of metrics (placeholder for actual type)
type MetricFamily struct {
	Name    string
	Help    string
	Type    string
	Metrics []interface{}
}

// NetworkCallbacks provides network event callbacks
type NetworkCallbacks interface {
	Connected(ctx context.Context, nodeID ids.NodeID, version interface{}) error
	Disconnected(ctx context.Context, nodeID ids.NodeID) error
}

// AppHandler handles application-level messages (e.g., Warp messages)
type AppHandler interface {
	// Request handles an application request
	Request(ctx context.Context, nodeID ids.NodeID, requestID uint32, deadline interface{}, request []byte) ([]byte, error)

	// Response handles an application response
	Response(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error

	// Gossip handles an application gossip message
	Gossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error
}
