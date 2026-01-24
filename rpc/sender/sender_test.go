// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sender

import (
	"testing"

	"github.com/luxfi/p2p"
)

// TestSenderServerInterface verifies that SenderServer interface is implemented
func TestSenderServerInterface(t *testing.T) {
	var _ SenderServer = (*ZAPServer)(nil)
}

// TestZAPClientInterface verifies that zapClient implements p2p.Sender
func TestZAPClientInterface(t *testing.T) {
	var _ p2p.Sender = (*zapClient)(nil)
}
