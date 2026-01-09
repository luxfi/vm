// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package proposervm

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

// TestVMSetPreferenceContextCancellation tests that SetPreference properly handles context cancellation
func TestVMSetPreferenceContextCancellation(t *testing.T) {
	require := require.New(t)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Create a VM (minimal setup for testing)
	vm := &VM{
		preferred: ids.Empty, // Start with empty preferred
	}

	// SetPreference should return context.Canceled error
	testID := ids.GenerateTestID()
	err := vm.SetPreference(ctx, testID)
	require.ErrorIs(err, context.Canceled, "SetPreference should fail with context.Canceled")
}

// TestVMSetPreferenceContextTimeout tests that SetPreference respects context timeout
func TestVMSetPreferenceContextTimeout(t *testing.T) {
	require := require.New(t)

	// Create a context with a very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for timeout to trigger
	time.Sleep(10 * time.Millisecond)

	// Create a VM
	vm := &VM{
		preferred: ids.Empty,
	}

	// SetPreference should return context.DeadlineExceeded error
	testID := ids.GenerateTestID()
	err := vm.SetPreference(ctx, testID)
	require.ErrorIs(err, context.DeadlineExceeded, "SetPreference should fail with context.DeadlineExceeded")
}

// TestVMSetPreferenceSameBlockNoCheck tests that same block preference short-circuits before context check
func TestVMSetPreferenceSameBlockNoCheck(t *testing.T) {
	require := require.New(t)

	testID := ids.GenerateTestID()

	// Create a VM with existing preferred block
	vm := &VM{
		preferred: testID,
	}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// SetPreference with same ID should succeed (short-circuits before context check)
	err := vm.SetPreference(ctx, testID)
	require.NoError(err, "SetPreference with same ID should succeed even with cancelled context")
}

// TestVMSetPreferenceContextCheckBeforeExpensiveOps tests that context is checked before expensive operations
func TestVMSetPreferenceContextCheckBeforeExpensiveOps(t *testing.T) {
	require := require.New(t)

	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	testID1 := ids.GenerateTestID()
	testID2 := ids.GenerateTestID()

	// Create a VM
	vm := &VM{
		preferred:      testID1,
		verifiedBlocks: make(map[ids.ID]PostForkBlock),
	}

	// Cancel context before calling SetPreference
	cancel()

	// SetPreference should fail at context check before trying to get post-fork block
	err := vm.SetPreference(ctx, testID2)
	require.ErrorIs(err, context.Canceled, "SetPreference should fail at first context check")
}
