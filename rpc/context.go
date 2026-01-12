// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"github.com/luxfi/consensus/runtime"
	validators "github.com/luxfi/consensus/validator"
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/protocol/p/warp"
	"github.com/luxfi/upgrade"
	"github.com/luxfi/vm/api/metrics"
	"github.com/luxfi/vm/chains/atomic"
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
	ValidatorState validators.State
}

// Ensure Context implements VMContext
var _ runtime.VMContext = (*Context)(nil)

// ToConsensusContext converts node Context to consensus Context
// This is explicit - we know exactly what we're doing
func (c *Context) ToConsensusContext() interface{} {
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
func (c *Context) GetLog() interface{} { return c.Log }

// GetSharedMemory implements VMContext
func (c *Context) GetSharedMemory() interface{} { return c.SharedMemory }

// GetMetrics implements VMContext
func (c *Context) GetMetrics() interface{} { return c.Metrics }

// GetValidatorState implements VMContext
func (c *Context) GetValidatorState() interface{} { return c.ValidatorState }

// GetBCLookup implements VMContext
func (c *Context) GetBCLookup() interface{} { return c.BCLookup }

// GetWarpSigner implements VMContext
func (c *Context) GetWarpSigner() interface{} { return c.WarpSigner }

// GetNetworkUpgrades implements VMContext
func (c *Context) GetNetworkUpgrades() interface{} { return c.NetworkUpgrades }
