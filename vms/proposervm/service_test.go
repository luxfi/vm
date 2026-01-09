// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package proposervm

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
	"github.com/luxfi/vm/vms/proposervm/proposer"
)

func TestServiceGetProposedHeight(t *testing.T) {
	require := require.New(t)

	// Create a proposervm with mocked core VM  using existing test setup
	activationTime := time.Unix(0, 0)
	durangoTime := time.Unix(0, 0)
	_, valState, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	// Set up validator state to return a known height
	currentPChainHeight := uint64(100)
	// GetMinimumHeightF is already set in initTestProposerVM, so we only need GetCurrentHeightF
	valState.GetCurrentHeightF = func(context.Context) (uint64, error) {
		return currentPChainHeight, nil
	}

	// Create the service
	service := &Service{vm: proVM}

	// Create test request
	req := httptest.NewRequest("POST", "/", nil)
	args := &GetProposedHeightArgs{}
	reply := &GetProposedHeightReply{}

	// Call GetProposedHeight
	require.NoError(service.GetProposedHeight(req, args, reply))

	// The proposed height should be >= the current P-Chain height
	require.GreaterOrEqual(reply.ProposedHeight, currentPChainHeight)
}

func TestNewHTTPHandler(t *testing.T) {
	require := require.New(t)

	// Use the existing test setup
	activationTime := time.Unix(0, 0)
	durangoTime := time.Unix(0, 0)
	_, valState, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	// The state and windower should already be initialized by initTestProposerVM
	if proVM.Windower == nil {
		networkID := ids.ID{}
		copy(networkID[:], []byte{byte(proVM.ctx.NetworkID)})
		proVM.Windower = proposer.New(valState, networkID, proVM.ctx.ChainID)
	}

	// Test creating the HTTP handler
	handler, err := NewHTTPHandler(proVM)
	require.NoError(err)
	require.NotNil(handler)
}

func TestCreateHandlersIncludesProposerVM(t *testing.T) {
	require := require.New(t)

	// Use the existing test setup
	activationTime := time.Unix(0, 0)
	durangoTime := time.Unix(0, 0)
	_, _, proVM, _ := initTestProposerVM(t, activationTime, durangoTime, 0)
	defer func() {
		require.NoError(proVM.Shutdown(context.Background()))
	}()

	// Get the handlers
	handlers, err := proVM.CreateHandlers(context.Background())
	require.NoError(err)
	require.NotNil(handlers)

	// Check that the proposervm handler is registered
	proposerHandler, ok := handlers["/proposervm"]
	require.True(ok, "proposervm handler should be registered")
	require.NotNil(proposerHandler)
}
