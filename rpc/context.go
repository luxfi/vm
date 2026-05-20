// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	"github.com/luxfi/upgrade"
	validators "github.com/luxfi/validators"
	"github.com/luxfi/vm/api/metrics"
	"github.com/luxfi/vm/chains/atomic"
	"github.com/luxfi/warp"
)

// Context is the node-specific context for RPC chain VM
type Context struct {
	NetworkID       uint32
	NetID           ids.ID
	ChainID         ids.ID
	NodeID          ids.NodeID
	PublicKey       *bls.PublicKey
	NetworkUpgrades upgrade.Config

	XChainID     ids.ID
	CChainID     ids.ID
	LUXAssetID   ids.ID
	ChainDataDir string

	Log            log.Logger
	SharedMemory   atomic.SharedMemory
	BCLookup       ids.AliaserReader
	Metrics        metrics.MultiGatherer
	WarpSigner     warp.Signer
	Sender         warp.Sender
	ValidatorState validators.State
}

// Ensure Context implements VMContext
var _ runtime.VMContext = (*Context)(nil)

// ToConsensusContext converts node Context to consensus Context
// This is explicit - we know exactly what we're doing
func (c *Context) ToConsensusRuntime() interface{} {
	// Return as interface{} - consensus layer decides how to use it
	// We don't pretend the types match - they don't
	return c
}

// PublicKeyBytes returns the public key as bytes
func (c *Context) PublicKeyBytes() []byte {
	if c.PublicKey == nil {
		return nil
	}
	return bls.PublicKeyToCompressedBytes(c.PublicKey)
}

// VMContext interface implementation

// GetNetworkID implements VMContext
func (c *Context) GetNetworkID() uint32 { return c.NetworkID }

// GetChainID implements VMContext
func (c *Context) GetChainID() ids.ID { return c.ChainID }

// GetNodeID implements VMContext
func (c *Context) GetNodeID() ids.NodeID { return c.NodeID }

// GetPublicKey implements VMContext
func (c *Context) GetPublicKey() []byte { return c.PublicKeyBytes() }

// GetXChainID implements VMContext
func (c *Context) GetXChainID() ids.ID { return c.XChainID }

// GetCChainID implements VMContext
func (c *Context) GetCChainID() ids.ID { return c.CChainID }

// GetAssetID implements VMContext
func (c *Context) GetAssetID() ids.ID { return c.LUXAssetID }

// GetChainDataDir implements VMContext
func (c *Context) GetChainDataDir() string { return c.ChainDataDir }

// GetLog implements VMContext
func (c *Context) GetLog() runtime.Logger { return c.Log }

// GetSharedMemory implements VMContext
func (c *Context) GetSharedMemory() runtime.SharedMemory { return c.SharedMemory }

// GetMetrics implements VMContext
func (c *Context) GetMetrics() runtime.Metrics { return c.Metrics }

// GetValidatorState implements VMContext
func (c *Context) GetValidatorState() runtime.ValidatorState { return c.ValidatorState }

// GetBCLookup implements VMContext
func (c *Context) GetBCLookup() runtime.BCLookup { return c.BCLookup }

// GetWarpSigner implements VMContext
func (c *Context) GetWarpSigner() runtime.WarpSigner { return c.WarpSigner }

// GetSender implements VMContext
func (c *Context) GetSender() warp.Sender { return c.Sender }

// NOTE: GetNetworkUpgrades was removed from the VMContext interface in
// the runtime decomplect (commit 3eea32ad — "rip NetworkUpgrades
// interface (14 always-true predicates) from Runtime + VMContext").
// Callers that need upgrade-config should read c.NetworkUpgrades
// directly. No backwards-compat shim — forwards only.
