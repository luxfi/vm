// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2019-2024, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package tmpnet

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

const (
	DefaultNetworkTimeout = 2 * time.Minute
)

// Flags is a map of node flags with helper methods
type Flags map[string]interface{}

// GetStringVal returns the string value for a flag, or empty string if not found or not a string
func (f Flags) GetStringVal(key string) string {
	if v, ok := f[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// Network represents a local test network
type Network struct {
	UUID                 string
	NetworkID            uint32
	Owner                string
	Dir                  string
	Nodes                []*Node
	DefaultRuntimeConfig NodeRuntimeConfig
	Genesis              interface{} // Can be []byte or *genesis.UnparsedConfig
	DefaultFlags         Flags

	// Track chains/chains
	Chains []*Chain
}

// Chain represents a chain in the network
type Chain struct {
	ChainID      ids.ID
	Chains       []*Chain
	ValidatorIDs []ids.NodeID
}

// Chain represents a blockchain in a chain
type Chain struct {
	ChainID   ids.ID
	VMID      ids.ID
	ChainName string
	Genesis   []byte
}

// NodeRuntimeConfig configures how nodes are run
type NodeRuntimeConfig struct {
	Process *ProcessRuntimeConfig
}

// ProcessRuntimeConfig configures process execution
type ProcessRuntimeConfig struct {
	LuxdPath    string
	LuxNodePath string // Alias for LuxdPath for CLI compatibility
	PluginDir   string
}

// ReadNetwork reads a network from its directory
func ReadNetwork(ctx context.Context, log log.Logger, networkDir string) (*Network, error) {
	networkPath := filepath.Join(networkDir, "network.json")
	data, err := os.ReadFile(networkPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read network config: %w", err)
	}

	var network Network
	if err := json.Unmarshal(data, &network); err != nil {
		return nil, fmt.Errorf("failed to parse network config: %w", err)
	}

	network.Dir = networkDir

	// Read nodes
	nodesDir := filepath.Join(networkDir, "nodes")
	entries, err := os.ReadDir(nodesDir)
	if err != nil {
		// No nodes directory is fine for new networks
		return &network, nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		nodeDir := filepath.Join(nodesDir, entry.Name())
		node, err := ReadNode(nodeDir)
		if err != nil {
			log.Warn("failed to read node", "dir", nodeDir, "error", err)
			continue
		}
		network.Nodes = append(network.Nodes, node)
	}

	return &network, nil
}

// Write writes the network configuration to disk
func (n *Network) Write() error {
	if n.Dir == "" {
		return fmt.Errorf("network directory not set")
	}

	if err := os.MkdirAll(n.Dir, 0755); err != nil {
		return fmt.Errorf("failed to create network directory: %w", err)
	}

	data, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal network config: %w", err)
	}

	networkPath := filepath.Join(n.Dir, "network.json")
	if err := os.WriteFile(networkPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write network config: %w", err)
	}

	return nil
}

// Start starts all nodes in the network
func (n *Network) Start(ctx context.Context, log log.Logger) error {
	for _, node := range n.Nodes {
		if err := node.Start(ctx, log); err != nil {
			return fmt.Errorf("failed to start node %s: %w", node.NodeID, err)
		}
	}
	return nil
}

// Stop stops all nodes in the network
func (n *Network) Stop(ctx context.Context) error {
	var lastErr error
	for _, node := range n.Nodes {
		if err := node.Stop(ctx); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// GetBootstrapIPsAndIDs returns the bootstrap IPs and IDs for the network
func (n *Network) GetBootstrapIPsAndIDs() ([]string, []string) {
	var ips, nodeIDs []string
	for _, node := range n.Nodes {
		if node.URI != "" {
			ips = append(ips, fmt.Sprintf("%s:%d", node.URI, node.StakingPort))
			nodeIDs = append(nodeIDs, node.NodeID.String())
		}
	}
	return ips, nodeIDs
}

// EnsureDefaultConfig ensures the network has default configuration
func (n *Network) EnsureDefaultConfig(log log.Logger) error {
	if n.Dir == "" {
		return fmt.Errorf("network directory not set")
	}
	if err := os.MkdirAll(n.Dir, 0755); err != nil {
		return fmt.Errorf("failed to create network directory: %w", err)
	}
	if n.DefaultFlags == nil {
		n.DefaultFlags = make(map[string]interface{})
	}
	return nil
}

// EnsureNodeConfig ensures a node has proper configuration for this network
func (n *Network) EnsureNodeConfig(node *Node) error {
	if node.DataDir == "" {
		if n.Dir == "" {
			return fmt.Errorf("network directory not set")
		}
		nodesDir := filepath.Join(n.Dir, "nodes")
		if err := os.MkdirAll(nodesDir, 0755); err != nil {
			return fmt.Errorf("failed to create nodes directory: %w", err)
		}
		node.DataDir = filepath.Join(nodesDir, node.NodeID.String())
	}
	if node.Flags == nil {
		node.Flags = make(map[string]interface{})
	}
	// Copy default flags
	for k, v := range n.DefaultFlags {
		if _, exists := node.Flags[k]; !exists {
			node.Flags[k] = v
		}
	}
	// Set runtime config from network default
	if node.RuntimeConfig == nil && n.DefaultRuntimeConfig.Process != nil {
		node.RuntimeConfig = &NodeRuntimeConfig{
			Process: &ProcessRuntimeConfig{
				LuxdPath:    n.DefaultRuntimeConfig.Process.LuxdPath,
				LuxNodePath: n.DefaultRuntimeConfig.Process.LuxNodePath,
				PluginDir:   n.DefaultRuntimeConfig.Process.PluginDir,
			},
		}
	}
	return nil
}
