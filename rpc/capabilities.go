// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

// VMKind represents the type of consensus data structure the VM supports.
type VMKind string

const (
	// VMKindChain indicates a linear blockchain (single-parent blocks)
	VMKindChain VMKind = "chain"
	// VMKindDAG indicates a directed acyclic graph (multi-parent vertices)
	VMKindDAG VMKind = "dag"
	// VMKindHybrid indicates support for both chain and DAG
	VMKindHybrid VMKind = "hybrid"
)

// VMFeature represents optional features a VM can support.
type VMFeature string

const (
	// Core block/vertex operations
	FeatureBuildBlock    VMFeature = "build_block"
	FeatureParseBlock    VMFeature = "parse_block"
	FeatureGetBlock      VMFeature = "get_block"
	FeatureVerifyBlock   VMFeature = "verify_block"
	FeatureAcceptBlock   VMFeature = "accept_block"
	FeatureRejectBlock   VMFeature = "reject_block"
	FeatureSetPreference VMFeature = "set_preference"

	// DAG-specific operations
	FeatureBuildVertex   VMFeature = "build_vertex"
	FeatureParseVertex   VMFeature = "parse_vertex"
	FeatureGetVertex     VMFeature = "get_vertex"
	FeatureVerifyVertex  VMFeature = "verify_vertex"
	FeatureAcceptVertex  VMFeature = "accept_vertex"
	FeatureRejectVertex  VMFeature = "reject_vertex"
	FeatureFrontierOps   VMFeature = "frontier_ops"

	// State and sync
	FeatureStateSync  VMFeature = "state_sync"
	FeatureStateSummary VMFeature = "state_summary"
	FeatureGetAncestors VMFeature = "get_ancestors"

	// Batched operations
	FeatureBatchedParse  VMFeature = "batched_parse"
	FeatureBatchedVerify VMFeature = "batched_verify"

	// Context-aware operations
	FeatureWithContext VMFeature = "with_context"

	// App messaging
	FeatureAppSender  VMFeature = "app_sender"
	FeatureAppHandler VMFeature = "app_handler"
)

// Capabilities describes what a VM supports.
type Capabilities struct {
	// Kind indicates chain, dag, or hybrid
	Kind VMKind `json:"kind"`

	// Features lists supported optional features
	Features []VMFeature `json:"features"`

	// Version of the capability protocol
	Version uint32 `json:"version"`

	// MinProtocolVersion is the minimum RPC protocol version supported
	MinProtocolVersion uint32 `json:"min_protocol_version"`

	// MaxProtocolVersion is the maximum RPC protocol version supported
	MaxProtocolVersion uint32 `json:"max_protocol_version"`
}

// CurrentCapabilitiesVersion is the current version of the capabilities protocol.
const CurrentCapabilitiesVersion uint32 = 1

// NewChainCapabilities returns default capabilities for a chain VM.
func NewChainCapabilities() *Capabilities {
	return &Capabilities{
		Kind:               VMKindChain,
		Version:            CurrentCapabilitiesVersion,
		MinProtocolVersion: 42,
		MaxProtocolVersion: 42,
		Features: []VMFeature{
			FeatureBuildBlock,
			FeatureParseBlock,
			FeatureGetBlock,
			FeatureVerifyBlock,
			FeatureAcceptBlock,
			FeatureRejectBlock,
			FeatureSetPreference,
			FeatureGetAncestors,
			FeatureAppSender,
			FeatureAppHandler,
		},
	}
}

// NewDAGCapabilities returns default capabilities for a DAG VM.
func NewDAGCapabilities() *Capabilities {
	return &Capabilities{
		Kind:               VMKindDAG,
		Version:            CurrentCapabilitiesVersion,
		MinProtocolVersion: 42,
		MaxProtocolVersion: 42,
		Features: []VMFeature{
			FeatureBuildVertex,
			FeatureParseVertex,
			FeatureGetVertex,
			FeatureVerifyVertex,
			FeatureAcceptVertex,
			FeatureRejectVertex,
			FeatureFrontierOps,
			FeatureGetAncestors,
			FeatureAppSender,
			FeatureAppHandler,
		},
	}
}

// NewHybridCapabilities returns capabilities for a VM that supports both chain and DAG.
func NewHybridCapabilities() *Capabilities {
	caps := NewChainCapabilities()
	caps.Kind = VMKindHybrid

	// Add DAG features
	dagCaps := NewDAGCapabilities()
	caps.Features = append(caps.Features, dagCaps.Features...)

	return caps
}

// SupportsFeature returns true if the VM supports the given feature.
func (c *Capabilities) SupportsFeature(feature VMFeature) bool {
	for _, f := range c.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// SupportsChain returns true if the VM supports chain operations.
func (c *Capabilities) SupportsChain() bool {
	return c.Kind == VMKindChain || c.Kind == VMKindHybrid
}

// SupportsDAG returns true if the VM supports DAG operations.
func (c *Capabilities) SupportsDAG() bool {
	return c.Kind == VMKindDAG || c.Kind == VMKindHybrid
}

// WithFeature adds a feature and returns the capabilities for chaining.
func (c *Capabilities) WithFeature(feature VMFeature) *Capabilities {
	if !c.SupportsFeature(feature) {
		c.Features = append(c.Features, feature)
	}
	return c
}

// WithStateSync adds state sync capability.
func (c *Capabilities) WithStateSync() *Capabilities {
	return c.WithFeature(FeatureStateSync).WithFeature(FeatureStateSummary)
}

// WithBatchedOps adds batched operation capability.
func (c *Capabilities) WithBatchedOps() *Capabilities {
	return c.WithFeature(FeatureBatchedParse).WithFeature(FeatureBatchedVerify)
}

// WithContext adds context-aware operation capability.
func (c *Capabilities) WithContext() *Capabilities {
	return c.WithFeature(FeatureWithContext)
}
