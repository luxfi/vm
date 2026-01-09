// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chains

import (
	validators "github.com/luxfi/consensus/validator"
	"github.com/luxfi/ids"
)

// Manager is the minimal chain manager interface needed by PlatformVM config.
type Manager interface {
	QueueChainCreation(ChainParameters)
}

// ChainParameters defines the chain being created.
type ChainParameters struct {
	// The ID of the blockchain being created.
	ID ids.ID
	// ID of the chain that validates this blockchain.
	ChainID ids.ID
	// The genesis data of this blockchain's ledger.
	GenesisData []byte
	// The ID of the VM this blockchain is running.
	VMID ids.ID
	// The IDs of the feature extensions this blockchain is running.
	FxIDs []ids.ID
	// Invariant: Only used when [ID] is the P-Chain ID.
	CustomBeacons validators.Manager
	// Name of the chain (used for HTTP routing alias, e.g., /ext/bc/zoo/rpc).
	Name string
}

// TestManager is a no-op Manager for tests.
var TestManager Manager = testManager{}

type testManager struct{}

func (testManager) QueueChainCreation(ChainParameters) {}
