// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2025, Lux Industries Inc All rights reserved.
// See the file LICENSE for licensing terms.

// Package rpc provides robust RPC handler registration with retries, health checks, and clear debugging.
// Follows Go principles: fail fast with clear errors, single responsibility, minimal dependencies.
package rpc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/vm/api/server"
)

var (
	// Errors follow Go convention: lowercase, descriptive, actionable
	errNilHandler         = errors.New("handler is nil")
	errNilServer          = errors.New("server is nil")
	errEmptyEndpoint      = errors.New("endpoint is empty")
	errRegistrationFailed = errors.New("handler registration failed")
	errHealthCheckFailed  = errors.New("health check failed")
)

// HandlerManager manages RPC handler registration with robust error handling and health checks.
// Single responsibility: reliable handler registration with observability.
type HandlerManager struct {
	server    server.Server
	log       log.Logger
	mu        sync.RWMutex
	routes    map[string]*RouteInfo // chainID -> route info
	retries   int                   // max registration retries
	retryWait time.Duration         // initial retry wait time
}

// RouteInfo contains complete information about a registered route.
// Everything needed for debugging in one place.
type RouteInfo struct {
	ChainID    ids.ID
	ChainAlias string
	Base       string   // e.g., "bc/C" or "bc/<chainID>"
	Endpoints  []string // e.g., ["/rpc", "/ws"]
	Handler    http.Handler
	Healthy    bool
	LastCheck  time.Time
}

// NewHandlerManager creates a handler manager with sensible defaults.
// Simple factory, no magic.
func NewHandlerManager(server server.Server, logger log.Logger) *HandlerManager {
	return &HandlerManager{
		server:    server,
		log:       logger,
		routes:    make(map[string]*RouteInfo),
		retries:   3,
		retryWait: 100 * time.Millisecond,
	}
}

// RegisterChainHandlers registers all handlers for a chain with retry logic and health checks.
// This is the main entry point - handles everything needed for robust registration.
func (m *HandlerManager) RegisterChainHandlers(
	ctx context.Context,
	chainID ids.ID,
	chainAlias string,
	handlers map[string]http.Handler,
) error {
	if m.server == nil {
		return errNilServer
	}

	m.log.Info("Starting chain handler registration",
		log.Stringer("chainID", chainID),
		log.String("alias", chainAlias),
		log.Int("handlerCount", len(handlers)))

	// Validate handlers first - fail fast
	if err := m.validateHandlers(handlers); err != nil {
		return fmt.Errorf("handler validation failed: %w", err)
	}

	// Build route info
	info := &RouteInfo{
		ChainID:    chainID,
		ChainAlias: chainAlias,
		Endpoints:  make([]string, 0, len(handlers)),
	}

	// Determine base paths
	bases := m.getBasePaths(chainID, chainAlias)

	// Register each handler with retries
	var registrationErrors []error
	for endpoint, handler := range handlers {
		info.Endpoints = append(info.Endpoints, endpoint)

		for _, base := range bases {
			if err := m.registerWithRetry(ctx, base, endpoint, handler); err != nil {
				registrationErrors = append(registrationErrors,
					fmt.Errorf("failed to register %s%s: %w", base, endpoint, err))
				m.log.Error("Handler registration failed",
					log.String("base", base),
					log.String("endpoint", endpoint),
					log.Err(err))
			} else {
				m.log.Info("Handler registered successfully",
					log.String("route", fmt.Sprintf("/ext/%s%s", base, endpoint)),
					log.Stringer("chainID", chainID))
			}
		}
	}

	// Store route info for monitoring
	m.mu.Lock()
	info.Base = bases[0]            // Primary base
	info.Handler = handlers["/rpc"] // Store primary handler for health checks
	m.routes[chainID.String()] = info
	m.mu.Unlock()

	// Run health checks
	if err := m.healthCheckRoute(info); err != nil {
		m.log.Warn("Health check failed for newly registered chain",
			log.Stringer("chainID", chainID),
			log.Err(err))
	}

	// Return aggregate error if any registrations failed
	if len(registrationErrors) > 0 {
		return fmt.Errorf("%w: %v", errRegistrationFailed, registrationErrors)
	}

	m.log.Info("Chain handler registration completed",
		log.Stringer("chainID", chainID),
		log.String("routes", strings.Join(m.getFullRoutes(bases, info.Endpoints), ", ")))

	return nil
}

// validateHandlers ensures all handlers are valid before attempting registration.
// Fail fast with clear errors - no silent failures.
func (m *HandlerManager) validateHandlers(handlers map[string]http.Handler) error {
	if len(handlers) == 0 {
		return errors.New("no handlers provided")
	}

	for endpoint, handler := range handlers {
		if handler == nil {
			return fmt.Errorf("%w for endpoint %s", errNilHandler, endpoint)
		}
		if endpoint == "" {
			return errEmptyEndpoint
		}
		// Ensure endpoint starts with /
		if !strings.HasPrefix(endpoint, "/") {
			return fmt.Errorf("endpoint %s must start with /", endpoint)
		}
	}
	return nil
}

// getBasePaths returns all base paths for a chain (with and without alias).
// Single source of truth for path construction.
func (m *HandlerManager) getBasePaths(chainID ids.ID, chainAlias string) []string {
	bases := []string{}

	// If we have an alias (like "C" for C-Chain), use it as primary
	if chainAlias != "" && chainAlias != chainID.String() {
		bases = append(bases, fmt.Sprintf("bc/%s", chainAlias))
	}

	// Always include the full chain ID path
	bases = append(bases, fmt.Sprintf("bc/%s", chainID.String()))

	return bases
}

// getFullRoutes constructs full route paths for logging.
// Clear, complete information for operators.
func (m *HandlerManager) getFullRoutes(bases []string, endpoints []string) []string {
	routes := []string{}
	for _, base := range bases {
		for _, endpoint := range endpoints {
			routes = append(routes, fmt.Sprintf("/ext/%s%s", base, endpoint))
		}
	}
	return routes
}

// registerWithRetry attempts registration with exponential backoff.
// Handles transient failures gracefully.
func (m *HandlerManager) registerWithRetry(
	ctx context.Context,
	base string,
	endpoint string,
	handler http.Handler,
) error {
	wait := m.retryWait
	var lastErr error

	for attempt := 0; attempt < m.retries; attempt++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Try registration
		if err := m.server.AddRoute(handler, base, endpoint); err == nil {
			return nil // Success!
		} else {
			lastErr = err
			m.log.Debug("Registration attempt failed, retrying",
				log.Int("attempt", attempt+1),
				log.String("base", base),
				log.String("endpoint", endpoint),
				log.Err(err))
		}

		// Don't wait after last attempt
		if attempt < m.retries-1 {
			select {
			case <-time.After(wait):
				wait *= 2 // Exponential backoff
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return fmt.Errorf("failed after %d attempts: %w", m.retries, lastErr)
}

// healthCheckRoute performs a basic health check on a registered route.
// Validates that handlers are actually responding.
func (m *HandlerManager) healthCheckRoute(info *RouteInfo) error {
	if info.Handler == nil {
		return fmt.Errorf("no handler to check for chain %s", info.ChainID)
	}

	// Create a test request
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}`))
	req.Header.Set("Content-Type", "application/json")

	// Record the response
	recorder := httptest.NewRecorder()

	// Call the handler
	info.Handler.ServeHTTP(recorder, req)

	// Check response
	info.LastCheck = time.Now()
	if recorder.Code == http.StatusOK || recorder.Code == http.StatusMethodNotAllowed {
		info.Healthy = true
		m.log.Debug("Health check passed",
			log.Stringer("chainID", info.ChainID),
			log.Int("status", recorder.Code))
		return nil
	}

	info.Healthy = false
	return fmt.Errorf("%w: status %d", errHealthCheckFailed, recorder.Code)
}

// GetRouteInfo returns information about a registered chain's routes.
// Useful for debugging and monitoring.
func (m *HandlerManager) GetRouteInfo(chainID ids.ID) (*RouteInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	info, exists := m.routes[chainID.String()]
	return info, exists
}

// GetAllRoutes returns all registered route information.
// Complete visibility for operators.
func (m *HandlerManager) GetAllRoutes() map[string]*RouteInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to prevent external modification
	routes := make(map[string]*RouteInfo, len(m.routes))
	for k, v := range m.routes {
		routes[k] = v
	}
	return routes
}

// HealthCheckAll performs health checks on all registered routes.
// Batch operation for monitoring systems.
func (m *HandlerManager) HealthCheckAll() map[string]bool {
	m.mu.RLock()
	routes := make([]*RouteInfo, 0, len(m.routes))
	for _, info := range m.routes {
		routes = append(routes, info)
	}
	m.mu.RUnlock()

	results := make(map[string]bool)
	for _, info := range routes {
		err := m.healthCheckRoute(info)
		results[info.ChainID.String()] = err == nil
	}

	return results
}

// SetRetryConfig allows customization of retry behavior.
// Flexibility for different deployment scenarios.
func (m *HandlerManager) SetRetryConfig(maxRetries int, initialWait time.Duration) {
	if maxRetries > 0 {
		m.retries = maxRetries
	}
	if initialWait > 0 {
		m.retryWait = initialWait
	}
}
