// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package server

// Generated from the interface, so a method added to Server is a regeneration
// away rather than a puzzle in another package's tests: without this the mock
// silently lagged by SetRootInfoProvider and registry's tests stopped
// compiling against it.
//go:generate go run go.uber.org/mock/mockgen -package=server -destination=mock_server.go github.com/luxfi/vm/api/server Server
