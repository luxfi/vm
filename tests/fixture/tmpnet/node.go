// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2019-2024, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package tmpnet

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	luxtls "github.com/luxfi/tls"
)

// Node represents a node in a local test network
type Node struct {
	NodeID         ids.NodeID
	URI            string
	StakingPort    uint64
	HTTPPort       uint64
	StakingAddress netip.AddrPort
	DataDir        string
	RuntimeConfig  *NodeRuntimeConfig
	Flags          Flags

	// BLS signing key
	SigningKey *bls.SecretKey

	// Staking credentials
	StakingKey  []byte
	StakingCert []byte

	// Process management
	cmd *exec.Cmd
}

// NodeConfig is the serialized node configuration
type NodeConfig struct {
	NodeID      string                 `json:"nodeID"`
	URI         string                 `json:"uri"`
	StakingPort uint64                 `json:"stakingPort"`
	HTTPPort    uint64                 `json:"httpPort"`
	DataDir     string                 `json:"dataDir"`
	Flags       map[string]interface{} `json:"flags"`
}

// NewNode creates a new node with default configuration
func NewNode() *Node {
	return &Node{
		Flags: make(Flags),
	}
}

// ReadNode reads a node configuration from its directory
func ReadNode(nodeDir string) (*Node, error) {
	configPath := filepath.Join(nodeDir, "node.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read node config: %w", err)
	}

	var config NodeConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse node config: %w", err)
	}

	nodeID, err := ids.NodeIDFromString(config.NodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse node ID: %w", err)
	}

	node := &Node{
		NodeID:      nodeID,
		URI:         config.URI,
		StakingPort: config.StakingPort,
		HTTPPort:    config.HTTPPort,
		DataDir:     config.DataDir,
		Flags:       config.Flags,
	}

	// Read staking credentials if present
	stakingKeyPath := filepath.Join(nodeDir, "staking", "staker.key")
	stakingCertPath := filepath.Join(nodeDir, "staking", "staker.crt")

	if keyData, err := os.ReadFile(stakingKeyPath); err == nil {
		node.StakingKey = keyData
	}
	if certData, err := os.ReadFile(stakingCertPath); err == nil {
		node.StakingCert = certData
	}

	return node, nil
}

// Write writes the node configuration to disk
func (n *Node) Write() error {
	if n.DataDir == "" {
		return fmt.Errorf("node data directory not set")
	}

	if err := os.MkdirAll(n.DataDir, 0755); err != nil {
		return fmt.Errorf("failed to create node directory: %w", err)
	}

	config := NodeConfig{
		NodeID:      n.NodeID.String(),
		URI:         n.URI,
		StakingPort: n.StakingPort,
		HTTPPort:    n.HTTPPort,
		DataDir:     n.DataDir,
		Flags:       n.Flags,
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal node config: %w", err)
	}

	configPath := filepath.Join(n.DataDir, "node.json")
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write node config: %w", err)
	}

	// Write staking credentials if present
	if len(n.StakingKey) > 0 || len(n.StakingCert) > 0 {
		stakingDir := filepath.Join(n.DataDir, "staking")
		if err := os.MkdirAll(stakingDir, 0700); err != nil {
			return fmt.Errorf("failed to create staking directory: %w", err)
		}

		if len(n.StakingKey) > 0 {
			keyPath := filepath.Join(stakingDir, "staker.key")
			if err := os.WriteFile(keyPath, n.StakingKey, 0600); err != nil {
				return fmt.Errorf("failed to write staking key: %w", err)
			}
		}

		if len(n.StakingCert) > 0 {
			certPath := filepath.Join(stakingDir, "staker.crt")
			if err := os.WriteFile(certPath, n.StakingCert, 0644); err != nil {
				return fmt.Errorf("failed to write staking cert: %w", err)
			}
		}
	}

	return nil
}

// Start starts the node process
func (n *Node) Start(ctx context.Context, log log.Logger) error {
	if n.RuntimeConfig == nil || n.RuntimeConfig.Process == nil {
		return fmt.Errorf("node runtime config not set")
	}

	luxdPath := n.RuntimeConfig.Process.LuxdPath
	if luxdPath == "" {
		return fmt.Errorf("luxd path not set")
	}

	args := []string{}
	for k, v := range n.Flags {
		args = append(args, fmt.Sprintf("--%s=%v", k, v))
	}

	n.cmd = exec.CommandContext(ctx, luxdPath, args...)
	n.cmd.Dir = n.DataDir

	if err := n.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start node: %w", err)
	}

	log.Info("started node", "nodeID", n.NodeID, "pid", n.cmd.Process.Pid)
	return nil
}

// Stop stops the node process
func (n *Node) Stop(ctx context.Context) error {
	if n.cmd == nil || n.cmd.Process == nil {
		return nil
	}

	// Send SIGTERM first
	if err := n.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		// Process may already be dead
		return nil
	}

	// Wait for process to exit
	done := make(chan error, 1)
	go func() {
		done <- n.cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		// Force kill if context expires
		n.cmd.Process.Kill()
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// InitiateStop sends SIGTERM to the node process without waiting
func (n *Node) InitiateStop() error {
	if n.cmd == nil || n.cmd.Process == nil {
		return nil
	}
	return n.cmd.Process.Signal(syscall.SIGTERM)
}

// WaitForStopped waits for the node process to exit
func (n *Node) WaitForStopped(ctx context.Context) error {
	if n.cmd == nil {
		return nil
	}
	done := make(chan error, 1)
	go func() {
		done <- n.cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// IsRunning returns true if the node process is running
func (n *Node) IsRunning() bool {
	if n.cmd == nil || n.cmd.Process == nil {
		return false
	}
	// Check if process is still running
	err := n.cmd.Process.Signal(syscall.Signal(0))
	return err == nil
}

// GetURI returns the node's HTTP URI
func (n *Node) GetURI() string {
	if n.URI == "" {
		return fmt.Sprintf("http://127.0.0.1:%d", n.HTTPPort)
	}
	return fmt.Sprintf("http://%s:%d", n.URI, n.HTTPPort)
}

// EnsureKeys ensures the node has staking credentials and derives NodeID from them
func (n *Node) EnsureKeys() error {
	if len(n.StakingKey) > 0 && len(n.StakingCert) > 0 && n.NodeID != ids.EmptyNodeID {
		// Already have keys and node ID
		return nil
	}

	// Generate new staking credentials
	cert, key, err := luxtls.NewCertAndKeyBytes()
	if err != nil {
		return fmt.Errorf("failed to generate staking credentials: %w", err)
	}

	n.StakingKey = key
	n.StakingCert = cert

	// Derive NodeID from certificate
	nodeID, err := deriveNodeID(cert)
	if err != nil {
		return fmt.Errorf("failed to derive node ID: %w", err)
	}
	n.NodeID = nodeID

	// Generate BLS signing key if not present
	if n.SigningKey == nil {
		sk, err := bls.NewSecretKey()
		if err != nil {
			return fmt.Errorf("failed to generate BLS key: %w", err)
		}
		n.SigningKey = sk
	}

	return nil
}

// deriveNodeID derives a NodeID from a staking certificate
func deriveNodeID(certBytes []byte) (ids.NodeID, error) {
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return ids.EmptyNodeID, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ids.EmptyNodeID, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Convert x509.Certificate to ids.Certificate
	idsCert := &ids.Certificate{
		Raw:       cert.Raw,
		PublicKey: cert.PublicKey,
	}

	return ids.NodeIDFromCert(idsCert), nil
}

// EnsureBLSSigningKey ensures the node has a BLS signing key
func (n *Node) EnsureBLSSigningKey() error {
	if n.SigningKey != nil {
		return nil
	}

	sk, err := bls.NewSecretKey()
	if err != nil {
		return fmt.Errorf("failed to generate BLS signing key: %w", err)
	}
	n.SigningKey = sk
	return nil
}

// GenerateNodeID generates a random NodeID for testing purposes
func GenerateNodeID() (ids.NodeID, error) {
	var nodeID ids.NodeID
	if _, err := rand.Read(nodeID[:]); err != nil {
		return ids.EmptyNodeID, fmt.Errorf("failed to generate random node ID: %w", err)
	}
	return nodeID, nil
}
