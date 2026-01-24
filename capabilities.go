package vm

import (
	"context"
	"net/http"

	"github.com/luxfi/ids"
)

// BlockBuilder is an optional capability for VMs that build blocks.
type BlockBuilder interface {
	BuildBlock(ctx context.Context) (Block, error)
}

// HandlerProvider is an optional capability for VMs that provide HTTP handlers.
type HandlerProvider interface {
	CreateHandlers(ctx context.Context) (map[string]http.Handler, error)
}

// EventSource is an optional capability for VMs that emit events.
type EventSource interface {
	WaitForEvent(ctx context.Context) (any, error)
}

// ConnectionAware is an optional capability for VMs that track peer connections.
type ConnectionAware interface {
	Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion any) error
	Disconnected(ctx context.Context, nodeID ids.NodeID) error
}

// HealthCheck is an optional capability for VMs that report health.
type HealthCheck interface {
	Health(ctx context.Context) (any, error)
}
