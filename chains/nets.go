// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chains

import (
	"errors"
	"sync"

	"github.com/luxfi/constants"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/nets"
)

var ErrNoPrimaryNetworkConfig = errors.New("no net config for primary network found")

// Nets holds the currently running chains on this node
type Nets struct {
	nodeID  ids.NodeID
	configs map[ids.ID]nets.Config

	lock   sync.RWMutex
	chains map[ids.ID]nets.Net
}

// GetOrCreate returns a chain running on this node, or creates one if it was
// not running before. Returns the chain and if the chain was created.
func (s *Nets) GetOrCreate(netID ids.ID) (nets.Net, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if chain, ok := s.chains[netID]; ok {
		return chain, false
	}

	// Default to the primary network config if a net config was not
	// specified
	config, ok := s.configs[netID]
	if !ok {
		config = s.configs[constants.PrimaryNetworkID]
	}

	chain := nets.New(s.nodeID, config)
	s.chains[netID] = chain

	return chain, true
}

// Bootstrapping returns the netIDs of any chains that are still
// bootstrapping.
func (s *Nets) Bootstrapping() []ids.ID {
	s.lock.RLock()
	defer s.lock.RUnlock()

	chainsBootstrapping := make([]ids.ID, 0, len(s.chains))
	for netID, chain := range s.chains {
		if !chain.IsBootstrapped() {
			chainsBootstrapping = append(chainsBootstrapping, netID)
		}
	}

	return chainsBootstrapping
}

// NewNets returns an instance of Nets
func NewNets(
	nodeID ids.NodeID,
	configs map[ids.ID]nets.Config,
) (*Nets, error) {
	if _, ok := configs[constants.PrimaryNetworkID]; !ok {
		return nil, ErrNoPrimaryNetworkConfig
	}

	s := &Nets{
		nodeID:  nodeID,
		configs: configs,
		chains:  make(map[ids.ID]nets.Net),
	}

	_, _ = s.GetOrCreate(constants.PrimaryNetworkID)
	return s, nil
}
