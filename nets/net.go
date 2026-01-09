// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.


package nets

import (
	"sync"

	"github.com/luxfi/ids"
	"github.com/luxfi/math/set"
)

type subnet struct {
	lock             sync.RWMutex
	bootstrapping    set.Set[ids.ID]
	bootstrapped     set.Set[ids.ID]
	once             sync.Once
	bootstrappedSema chan struct{}
	config           Config
	myNodeID         ids.NodeID
}

var _ Net = (*subnet)(nil)

type Allower interface {
	// IsAllowed filters out nodes that are not allowed to connect to this subnet
	IsAllowed(nodeID ids.NodeID, isValidator bool) bool
}

// Net keeps track of the currently bootstrapping chains in a subnet. If no
// chains in the net are currently bootstrapping, the net is considered
// bootstrapped.
type Net interface {
	// IsBootstrapped returns true if the chains in this subnet are done bootstrapping
	IsBootstrapped() bool

	// Bootstrapped marks the chain as done bootstrapping
	Bootstrapped(chainID ids.ID)

	// OnBootstrapCompleted is called when bootstrapping completes
	OnBootstrapCompleted() error

	// AddChain adds a chain to this Net
	AddChain(chainID ids.ID) bool

	// Config returns config of this Net
	Config() Config

	Allower
}

type net struct {
	lock             sync.RWMutex
	bootstrapping    set.Set[ids.ID]
	bootstrapped     set.Set[ids.ID]
	once             sync.Once
	bootstrappedSema chan struct{}
	config           Config
	myNodeID         ids.NodeID
}

func New(myNodeID ids.NodeID, config Config) Net {
	return &subnet{
		bootstrapping:    make(set.Set[ids.ID]),
		bootstrapped:     make(set.Set[ids.ID]),
		bootstrappedSema: make(chan struct{}),
		config:           config,
		myNodeID:         myNodeID,
	}
}

func (s *subnet) IsBootstrapped() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.bootstrapping.Len() == 0
}

func (s *subnet) Bootstrapped(chainID ids.ID) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.bootstrapping.Remove(chainID)
	s.bootstrapped.Add(chainID)
	if s.bootstrapping.Len() > 0 {
		return
	}

	s.once.Do(func() {
		close(s.bootstrappedSema)
	})
}

func (s *subnet) AllBootstrapped() <-chan struct{} {
	return s.bootstrappedSema
}

func (s *subnet) OnBootstrapCompleted() error {
	// Mark net as having completed bootstrap
	// This is called when all chains in the net have bootstrapped
	return nil
}

func (s *subnet) OnBootstrapStarted() error {
	// Mark net as starting bootstrap
	return nil
}

func (s *subnet) AddChain(chainID ids.ID) bool {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.bootstrapping.Contains(chainID) || s.bootstrapped.Contains(chainID) {
		return false
	}

	s.bootstrapping.Add(chainID)
	return true
}

func (s *subnet) Config() Config {
	return s.config
}

func (s *subnet) IsAllowed(nodeID ids.NodeID, isValidator bool) bool {
	// Case 1: NodeID is this node
	// Case 2: This net is not validator-only subnet
	// Case 3: NodeID is a validator for this chain
	// Case 4: NodeID is explicitly allowed whether it's net validator or not
	return nodeID == s.myNodeID ||
		!s.config.ValidatorOnly ||
		isValidator ||
		s.config.AllowedNodes.Contains(nodeID)
}
