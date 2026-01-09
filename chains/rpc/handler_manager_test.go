// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	consensusctx "github.com/luxfi/consensus/context"
	consensuscore "github.com/luxfi/consensus/core"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/stretchr/testify/require"
)

// mockServer implements a test server for handler registration
type mockServer struct {
	routes      map[string]http.Handler
	failCount   int
	maxFailures int
	returnError error
	aliases     map[string][]string
}

func newMockServer() *mockServer {
	return &mockServer{
		routes:      make(map[string]http.Handler),
		maxFailures: 0,
		aliases:     make(map[string][]string),
	}
}

func (s *mockServer) AddRoute(handler http.Handler, base, endpoint string) error {
	// Simulate transient failures for retry testing
	if s.failCount < s.maxFailures {
		s.failCount++
		return errors.New("transient failure")
	}

	// Return configured error if any
	if s.returnError != nil {
		return s.returnError
	}

	// Store the route
	key := base + endpoint
	s.routes[key] = handler
	return nil
}

func (s *mockServer) AddAliases(endpoint string, aliases ...string) error {
	s.aliases[endpoint] = aliases
	return nil
}

func (s *mockServer) AddRouteWithReadLock(handler http.Handler, base, endpoint string) error {
	return s.AddRoute(handler, base, endpoint)
}

func (s *mockServer) AddAliasesWithReadLock(endpoint string, aliases ...string) error {
	return s.AddAliases(endpoint, aliases...)
}

func (s *mockServer) Dispatch() error { return nil }
func (s *mockServer) RegisterChain(chainName string, ctx *consensusctx.Context, vm consensuscore.VM) {
}
func (s *mockServer) Shutdown() error { return nil }

func TestHandlerManager_RegisterChainHandlers(t *testing.T) {
	tests := []struct {
		name         string
		chainID      ids.ID
		chainAlias   string
		handlers     map[string]http.Handler
		serverError  error
		expectError  bool
		expectRoutes int
	}{
		{
			name:       "successful registration with alias",
			chainID:    ids.GenerateTestID(),
			chainAlias: "C",
			handlers: map[string]http.Handler{
				"/rpc": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
				"/ws": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
			},
			expectError:  false,
			expectRoutes: 4, // 2 endpoints × 2 bases (alias + ID)
		},
		{
			name:    "successful registration without alias",
			chainID: ids.GenerateTestID(),
			handlers: map[string]http.Handler{
				"/rpc": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
			},
			expectError:  false,
			expectRoutes: 1,
		},
		{
			name:        "nil handler validation",
			chainID:     ids.GenerateTestID(),
			chainAlias:  "X",
			handlers:    map[string]http.Handler{"/rpc": nil},
			expectError: true,
		},
		{
			name:        "empty endpoint validation",
			chainID:     ids.GenerateTestID(),
			handlers:    map[string]http.Handler{"": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})},
			expectError: true,
		},
		{
			name:        "no handlers provided",
			chainID:     ids.GenerateTestID(),
			handlers:    map[string]http.Handler{},
			expectError: true,
		},
		{
			name:        "invalid endpoint format",
			chainID:     ids.GenerateTestID(),
			handlers:    map[string]http.Handler{"rpc": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			server := newMockServer()
			server.returnError = tt.serverError
			logger := log.NewNoOpLogger()
			manager := NewHandlerManager(server, logger)

			// Execute
			ctx := context.Background()
			err := manager.RegisterChainHandlers(ctx, tt.chainID, tt.chainAlias, tt.handlers)

			// Verify
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Len(t, server.routes, tt.expectRoutes)

				// Verify route info was stored
				info, exists := manager.GetRouteInfo(tt.chainID)
				require.True(t, exists)
				require.Equal(t, tt.chainID, info.ChainID)
				require.Equal(t, tt.chainAlias, info.ChainAlias)
			}
		})
	}
}

func TestHandlerManager_RetryLogic(t *testing.T) {
	// Setup server that fails twice then succeeds
	server := newMockServer()
	server.maxFailures = 2

	logger := log.NewNoOpLogger()
	manager := NewHandlerManager(server, logger)
	manager.SetRetryConfig(3, 10*time.Millisecond)

	// Create test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Register with retries
	ctx := context.Background()
	chainID := ids.GenerateTestID()
	require.NoError(t, manager.RegisterChainHandlers(ctx, chainID, "TEST", map[string]http.Handler{
		"/rpc": handler,
	}))
	require.Equal(t, 2, server.failCount) // Failed twice, succeeded on third try
	require.Len(t, server.routes, 2)      // Both alias and ID routes
}

func TestHandlerManager_HealthCheck(t *testing.T) {
	server := newMockServer()
	logger := log.NewNoOpLogger()
	manager := NewHandlerManager(server, logger)

	// Register a healthy handler
	healthyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","result":"test","id":1}`))
	})

	// Register an unhealthy handler
	unhealthyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	ctx := context.Background()
	chainID1 := ids.GenerateTestID()
	chainID2 := ids.GenerateTestID()

	// Register healthy chain
	require.NoError(t, manager.RegisterChainHandlers(ctx, chainID1, "", map[string]http.Handler{
		"/rpc": healthyHandler,
	}))

	// Register unhealthy chain
	// Registration succeeds even if health check fails
	require.NoError(t, manager.RegisterChainHandlers(ctx, chainID2, "", map[string]http.Handler{
		"/rpc": unhealthyHandler,
	})) // Registration should succeed regardless of handler health

	// Check health status
	results := manager.HealthCheckAll()
	require.True(t, results[chainID1.String()])
	require.False(t, results[chainID2.String()])
}

func TestHandlerManager_GetBasePaths(t *testing.T) {
	manager := &HandlerManager{}
	chainID := ids.GenerateTestID()

	// Test with alias
	bases := manager.getBasePaths(chainID, "C")
	require.Equal(t, []string{"bc/C", "bc/" + chainID.String()}, bases)

	// Test without alias
	bases = manager.getBasePaths(chainID, "")
	require.Equal(t, []string{"bc/" + chainID.String()}, bases)

	// Test when alias equals chain ID (shouldn't duplicate)
	bases = manager.getBasePaths(chainID, chainID.String())
	require.Equal(t, []string{"bc/" + chainID.String()}, bases)
}

func TestHandlerManager_ContextCancellation(t *testing.T) {
	// Create a server that delays to test cancellation
	server := &mockServer{
		routes:      make(map[string]http.Handler),
		returnError: errors.New("slow server"),
	}

	logger := log.NewNoOpLogger()
	manager := NewHandlerManager(server, logger)
	manager.SetRetryConfig(10, 100*time.Millisecond) // Many retries with delays

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Try to register - should fail with context error
	chainID := ids.GenerateTestID()
	err := manager.RegisterChainHandlers(ctx, chainID, "", map[string]http.Handler{
		"/rpc": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "context canceled")
}

// Benchmark to ensure performance doesn't degrade
func BenchmarkHandlerRegistration(b *testing.B) {
	server := newMockServer()
	logger := log.NewNoOpLogger()
	manager := NewHandlerManager(server, logger)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		chainID := ids.GenerateTestID()
		manager.RegisterChainHandlers(ctx, chainID, "TEST", map[string]http.Handler{
			"/rpc": handler,
			"/ws":  handler,
		})
	}
}
