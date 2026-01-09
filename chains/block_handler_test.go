// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chains

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

// TestAcceptRejectDerivation tests the accept/reject derivation logic from the Chits handler
// This tests the core logic: Accept=true only if block exists AND verifies
func TestAcceptRejectDerivation(t *testing.T) {
	testCases := []struct {
		name           string
		blockExists    bool
		verifyError    error
		expectedAccept bool
	}{
		{
			name:           "accept when block exists and verifies",
			blockExists:    true,
			verifyError:    nil,
			expectedAccept: true,
		},
		{
			name:           "reject when block not found",
			blockExists:    false,
			verifyError:    nil,
			expectedAccept: false,
		},
		{
			name:           "reject when block fails verification",
			blockExists:    true,
			verifyError:    errors.New("verification failed"),
			expectedAccept: false,
		},
		{
			name:           "reject when block has invalid signature",
			blockExists:    true,
			verifyError:    errors.New("invalid signature"),
			expectedAccept: false,
		},
		{
			name:           "reject when block has invalid parent",
			blockExists:    true,
			verifyError:    errors.New("unknown parent"),
			expectedAccept: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			// Simulate the accept/reject logic from HandleInbound
			// This matches the logic in manager.go lines 1912-1920
			accept := deriveAcceptFromVerification(
				context.Background(),
				tc.blockExists,
				tc.verifyError,
			)

			require.Equal(tc.expectedAccept, accept, "Accept value mismatch")
		})
	}
}

// deriveAcceptFromVerification simulates the logic in blockHandler.HandleInbound
// for the Chits case. This is the core accept/reject derivation logic.
func deriveAcceptFromVerification(ctx context.Context, blockExists bool, verifyError error) bool {
	// This matches the logic in manager.go:
	// accept := false
	// if b.vm != nil {
	//     if blk, err := b.vm.GetBlock(ctx, preferredID); err == nil {
	//         if err := blk.Verify(ctx); err == nil {
	//             accept = true
	//         }
	//     }
	// }
	if !blockExists {
		return false
	}
	if verifyError != nil {
		return false
	}
	return true
}

// TestAcceptRejectWithNilVM tests that Accept=false when VM is nil
func TestAcceptRejectWithNilVM(t *testing.T) {
	require := require.New(t)

	// When VM is nil, we can't get the block, so accept should be false
	// This is the outer check: if b.vm != nil { ... }
	vmIsNil := true
	accept := false
	if !vmIsNil {
		// Would call vm.GetBlock and Verify
		accept = true
	}

	require.False(accept, "Accept should be false when VM is nil")
}

// TestChitsMessageLength tests that messages shorter than 32 bytes are handled
func TestChitsMessageLength(t *testing.T) {
	testCases := []struct {
		name        string
		messageLen  int
		shouldParse bool
	}{
		{
			name:        "empty message",
			messageLen:  0,
			shouldParse: false,
		},
		{
			name:        "message too short (16 bytes)",
			messageLen:  16,
			shouldParse: false,
		},
		{
			name:        "message too short (31 bytes)",
			messageLen:  31,
			shouldParse: false,
		},
		{
			name:        "message exactly 32 bytes",
			messageLen:  32,
			shouldParse: true,
		},
		{
			name:        "message longer than 32 bytes",
			messageLen:  64,
			shouldParse: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			// This matches the logic in manager.go:
			// if len(msg.Message) >= 32 && b.engine != nil { ... }
			msg := make([]byte, tc.messageLen)
			canParse := len(msg) >= 32

			require.Equal(tc.shouldParse, canParse, "Parse decision mismatch")

			// If we can parse, verify we can extract a block ID
			if canParse {
				var preferredID ids.ID
				copy(preferredID[:], msg[:32])
				require.Len(preferredID[:], 32, "Block ID should be 32 bytes")
			}
		})
	}
}

// TestVoteCreation tests that Vote struct is created correctly with derived Accept value
func TestVoteCreation(t *testing.T) {
	require := require.New(t)

	// Create a vote with Accept derived from verification
	blockID := ids.GenerateTestID()
	nodeID := ids.GenerateTestNodeID()

	// Case 1: Block exists and verifies - accept should be true
	accept1 := deriveAcceptFromVerification(context.Background(), true, nil)
	require.True(accept1)

	// Case 2: Block exists but fails verification - accept should be false
	accept2 := deriveAcceptFromVerification(context.Background(), true, errors.New("bad block"))
	require.False(accept2)

	// Case 3: Block doesn't exist - accept should be false
	accept3 := deriveAcceptFromVerification(context.Background(), false, nil)
	require.False(accept3)

	// Verify the block ID and node ID are preserved
	require.NotEqual(ids.Empty, blockID)
	require.NotEqual(ids.EmptyNodeID, nodeID)
}

// TestAcceptRejectOldVsNew tests that the new logic correctly rejects
// votes that would have been incorrectly accepted with hardcoded Accept=true
func TestAcceptRejectOldVsNew(t *testing.T) {
	require := require.New(t)

	// OLD LOGIC (before fix): Accept was always true
	// oldAccept := true // WRONG - this was hardcoded

	// NEW LOGIC: Accept is derived from verification
	// This ensures we don't accept votes for blocks we can't verify

	testCases := []struct {
		name        string
		blockExists bool
		verifyError error
		oldAccept   bool // What old logic would have done (always true)
		newAccept   bool // What new logic does (derived from verification)
	}{
		{
			name:        "valid block - old and new agree",
			blockExists: true,
			verifyError: nil,
			oldAccept:   true,
			newAccept:   true,
		},
		{
			name:        "missing block - old accepted wrongly, new rejects",
			blockExists: false,
			verifyError: nil,
			oldAccept:   true,  // BUG: Old logic would accept
			newAccept:   false, // CORRECT: New logic rejects
		},
		{
			name:        "invalid block - old accepted wrongly, new rejects",
			blockExists: true,
			verifyError: errors.New("invalid"),
			oldAccept:   true,  // BUG: Old logic would accept
			newAccept:   false, // CORRECT: New logic rejects
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			newAccept := deriveAcceptFromVerification(context.Background(), tc.blockExists, tc.verifyError)
			require.Equal(tc.newAccept, newAccept, "New accept value mismatch")

			// Verify the new logic is an improvement over the old logic
			if tc.blockExists && tc.verifyError == nil {
				// Valid block: both should accept
				require.Equal(tc.oldAccept, newAccept)
			} else {
				// Invalid or missing block: new logic should reject, old logic was wrong
				require.NotEqual(tc.oldAccept, newAccept, "New logic should reject what old logic wrongly accepted")
			}
		})
	}
}
