// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2025, Lux Industries Inc All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"context"
	"fmt"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/vm/api/server"
)

// IntegrationExample shows how to modify the existing createChain function in manager.go.
// This replaces lines 941-990 with cleaner, more robust code.
func IntegrationExample(
	ctx context.Context,
	chainID ids.ID,
	vm interface{},
	server server.Server,
	logger log.Logger,
	cChainID ids.ID,
	pChainID ids.ID,
	isDevMode bool,
) error {
	// BEFORE: 50+ lines of complex type checking and error-prone registration
	// AFTER: Clean, robust registration with proper error handling

	// Step 1: Create the registrar
	registrar := NewChainHandlerRegistrar(server, logger, cChainID, pChainID)

	// Step 2: Configure based on environment
	if isDevMode {
		// Development: Fast failures for quick iteration
		registrar.SetRetryConfig(2, 50*time.Millisecond)
		logger.Info("Using development handler registration settings")
	} else {
		// Production: More robust with retries
		registrar.SetRetryConfig(5, 200*time.Millisecond)
		logger.Info("Using production handler registration settings")
	}

	// Step 3: Register handlers (replaces all the complex VM type checking)
	startTime := time.Now()
	err := registrar.RegisterChainHandlers(ctx, chainID, vm)
	duration := time.Since(startTime)

	// Step 4: Handle registration result
	if err != nil {
		// Log error but don't fail chain creation
		// Handlers are not critical for chain operation
		logger.Error("RPC handler registration failed",
			log.Stringer("chainID", chainID),
			log.Err(err),
			log.Duration("duration", duration),
			log.String("action", "Chain will operate without HTTP/RPC access"))

		// Could emit metrics here if available
		// metric.HandlerRegistrationFailed.Inc()

		// Non-fatal: return nil to allow chain to continue
		// Change to 'return err' if you want this to be fatal
		return nil
	}

	// Step 5: Log success with useful information
	if info, exists := registrar.GetRouteInfo(chainID); exists {
		logger.Info("RPC handlers registered successfully",
			log.Stringer("chainID", chainID),
			log.String("alias", info.ChainAlias),
			log.Strings("endpoints", info.Endpoints),
			log.Duration("duration", duration),
			log.Bool("healthCheckPassed", info.Healthy))

		// Print developer-friendly message
		if isDevMode && len(info.Endpoints) > 0 {
			baseURL := "http://localhost:9630"
			fmt.Printf("\n✅ Chain %s RPC endpoints ready:\n", chainID)
			for _, endpoint := range info.Endpoints {
				if info.ChainAlias != "" {
					fmt.Printf("   %s/ext/bc/%s%s\n", baseURL, info.ChainAlias, endpoint)
				}
				fmt.Printf("   %s/ext/bc/%s%s\n", baseURL, chainID, endpoint)
			}
			fmt.Println()
		}
	}

	// Step 6: Schedule async health monitoring (optional)
	if !isDevMode { // Only in production
		go monitorHandlerHealth(ctx, registrar, chainID, logger)
	}

	return nil
}

// monitorHandlerHealth runs periodic health checks in the background.
// This helps detect and log handler issues early.
func monitorHandlerHealth(
	ctx context.Context,
	registrar *ChainHandlerRegistrar,
	chainID ids.ID,
	logger log.Logger,
) {
	// Initial delay to let chain fully initialize
	select {
	case <-time.After(10 * time.Second):
	case <-ctx.Done():
		return
	}

	// Run initial health check
	checkHealth(registrar, chainID, logger)

	// Periodic health checks
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			checkHealth(registrar, chainID, logger)
		case <-ctx.Done():
			return
		}
	}
}

// checkHealth performs a health check and logs results.
func checkHealth(registrar *ChainHandlerRegistrar, chainID ids.ID, logger log.Logger) {
	results := registrar.HealthCheckAll()

	for chainIDStr, healthy := range results {
		if chainIDStr == chainID.String() {
			if healthy {
				logger.Debug("Handler health check passed",
					log.String("chainID", chainIDStr))
			} else {
				logger.Warn("Handler health check failed",
					log.String("chainID", chainIDStr),
					log.String("action", "Will continue monitoring"))
			}
		}
	}
}

// MinimalIntegration shows the absolute minimum code needed.
// This is what you'd actually put in manager.go.
func MinimalIntegration(
	ctx context.Context,
	chainID ids.ID,
	vm interface{},
	server server.Server,
	logger log.Logger,
	cChainID ids.ID,
) error {
	// Just three lines to replace 50+ lines of complex code!
	registrar := NewChainHandlerRegistrar(server, logger, cChainID, ids.Empty)
	if err := registrar.RegisterChainHandlers(ctx, chainID, vm); err != nil {
		logger.Error("Handler registration failed", log.Err(err))
	}
	return nil // Non-fatal
}