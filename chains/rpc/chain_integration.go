// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2025, Lux Industries Inc All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/vm/api/server"
	"github.com/luxfi/vm/vms"
)

// ChainHandlerRegistrar provides a clean interface for chain manager to register handlers.
// This replaces the inline registration logic with a more robust, testable solution.
type ChainHandlerRegistrar struct {
	manager   *HandlerManager
	server    server.Server
	log       log.Logger
	cChainID  ids.ID // Special handling for C-Chain
	pChainID  ids.ID // Platform chain ID for validation
}

// NewChainHandlerRegistrar creates a registrar for chain handler registration.
// Encapsulates all the registration logic in one place.
func NewChainHandlerRegistrar(
	server server.Server,
	logger log.Logger,
	cChainID ids.ID,
	pChainID ids.ID,
) *ChainHandlerRegistrar {
	return &ChainHandlerRegistrar{
		manager:  NewHandlerManager(server, logger),
		server:   server,
		log:      logger,
		cChainID: cChainID,
		pChainID: pChainID,
	}
}

// RegisterChainHandlers is the main entry point from chain manager.
// Handles all the complexity of VM type checking and handler extraction.
func (r *ChainHandlerRegistrar) RegisterChainHandlers(
	ctx context.Context,
	chainID ids.ID,
	vm interface{},
) error {
	r.log.Info("Attempting to register chain handlers",
		log.Stringer("chainID", chainID),
		log.String("vmType", fmt.Sprintf("%T", vm)))

	// Don't register handlers for Platform VM
	if chainID == r.pChainID {
		r.log.Debug("Skipping handler registration for Platform VM")
		return nil
	}

	// Extract handlers from VM
	handlers, err := r.extractHandlers(ctx, vm)
	if err != nil {
		return fmt.Errorf("failed to extract handlers: %w", err)
	}

	if len(handlers) == 0 {
		r.log.Info("VM does not provide any handlers",
			log.Stringer("chainID", chainID))
		return nil
	}

	// Determine chain alias (special case for C-Chain)
	alias := r.getChainAlias(chainID)

	// Register with robust handler manager
	return r.manager.RegisterChainHandlers(ctx, chainID, alias, handlers)
}

// extractHandlers attempts to get handlers from the VM using multiple strategies.
// Handles different VM wrapper types gracefully.
func (r *ChainHandlerRegistrar) extractHandlers(
	ctx context.Context,
	vm interface{},
) (map[string]http.Handler, error) {
	// First try direct interface check
	if provider, ok := vm.(vms.HandlerProvider); ok {
		r.log.Debug("VM directly implements HandlerProvider")
		return provider.CreateHandlers(ctx)
	}

	// Try using the delegate helper (handles wrapped VMs)
	handlers, err := vms.DelegateHandlers(ctx, vm)
	if err != nil {
		return nil, fmt.Errorf("handler delegation failed: %w", err)
	}

	if len(handlers) > 0 {
		r.log.Debug("Successfully extracted handlers via delegation",
			log.Int("count", len(handlers)))
	}

	return handlers, nil
}

// getChainAlias returns the appropriate alias for a chain.
// C-Chain gets special treatment, others use their ID.
func (r *ChainHandlerRegistrar) getChainAlias(chainID ids.ID) string {
	if chainID == r.cChainID {
		return "C"
	}
	// Could extend this for X-Chain and P-Chain if needed
	return ""
}

// GetRouteInfo returns information about a specific chain's registered routes.
// Useful for debugging and operational visibility.
func (r *ChainHandlerRegistrar) GetRouteInfo(chainID ids.ID) (*RouteInfo, bool) {
	return r.manager.GetRouteInfo(chainID)
}

// GetAllRoutes returns all registered routes across all chains.
// Complete visibility for monitoring and debugging.
func (r *ChainHandlerRegistrar) GetAllRoutes() map[string]*RouteInfo {
	return r.manager.GetAllRoutes()
}

// HealthCheckAll performs health checks on all registered routes.
// Returns a map of chainID -> healthy status.
func (r *ChainHandlerRegistrar) HealthCheckAll() map[string]bool {
	return r.manager.HealthCheckAll()
}

// SetRetryConfig allows tuning of retry behavior for different environments.
// Production might want more retries, dev might want faster failures.
func (r *ChainHandlerRegistrar) SetRetryConfig(maxRetries int, initialWait time.Duration) {
	r.manager.SetRetryConfig(maxRetries, initialWait)
}

// ValidateEndpoint performs a test request against a specific endpoint.
// Useful for debugging specific handler issues.
func (r *ChainHandlerRegistrar) ValidateEndpoint(
	chainID ids.ID,
	endpoint string,
) error {
	info, exists := r.manager.GetRouteInfo(chainID)
	if !exists {
		return fmt.Errorf("no routes registered for chain %s", chainID)
	}

	// Build the full URL
	fullURL := fmt.Sprintf("/ext/%s%s", info.Base, endpoint)

	r.log.Info("Validating endpoint",
		log.Stringer("chainID", chainID),
		log.String("url", fullURL))

	// Could extend this to actually make an HTTP request to validate
	// For now, just check if the endpoint was registered
	for _, registered := range info.Endpoints {
		if registered == endpoint {
			return nil
		}
	}

	return fmt.Errorf("endpoint %s not found in registered endpoints: %v",
		endpoint, info.Endpoints)
}