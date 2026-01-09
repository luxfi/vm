// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package e2e provides testing infrastructure for end-to-end tests
package e2e

import (
	"context"
	"flag"

	"github.com/luxfi/vm/tests/fixture/tmpnet"
)

// FlagVars holds test configuration flags
type FlagVars struct {
	NetworkDir           string
	ReuseNetwork         bool
	RestartNetwork       bool
	StopNetwork          bool
	NetworkShutdownDelay string
}

// RegisterFlags registers e2e test flags and returns a FlagVars instance
func RegisterFlags() *FlagVars {
	vars := &FlagVars{}
	flag.StringVar(&vars.NetworkDir, "network-dir", "", "Directory containing a persistent network to use")
	flag.BoolVar(&vars.ReuseNetwork, "reuse-network", false, "Reuse existing network")
	flag.BoolVar(&vars.RestartNetwork, "restart-network", false, "Restart network before testing")
	flag.BoolVar(&vars.StopNetwork, "stop-network", false, "Stop network after testing")
	flag.StringVar(&vars.NetworkShutdownDelay, "network-shutdown-delay", "", "Delay before shutting down network")
	return vars
}

// TestContext holds test context
type TestContext struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// NewTestContext creates a new test context
func NewTestContext() *TestContext {
	ctx, cancel := context.WithCancel(context.Background())
	return &TestContext{ctx: ctx, cancel: cancel}
}

// DefaultContext returns the default context
func (tc *TestContext) DefaultContext() context.Context {
	return tc.ctx
}

// TestEnvironment holds test environment state
type TestEnvironment struct {
	tc       *TestContext
	flagVars *FlagVars
	network  *tmpnet.Network
}

// NewTestEnvironment creates a new test environment
func NewTestEnvironment(tc *TestContext, flagVars *FlagVars, network *tmpnet.Network) *TestEnvironment {
	return &TestEnvironment{
		tc:       tc,
		flagVars: flagVars,
		network:  network,
	}
}

// Marshal serializes the environment
func (te *TestEnvironment) Marshal() []byte {
	return []byte{}
}

// Unmarshal deserializes environment bytes
func (te *TestEnvironment) Unmarshal(data []byte) error {
	return nil
}

// GetNetwork returns the test network
func (te *TestEnvironment) GetNetwork() *tmpnet.Network {
	return te.network
}
