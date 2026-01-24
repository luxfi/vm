//go:build grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sender

import (
	"testing"

	"github.com/luxfi/p2p"
	senderpb "github.com/luxfi/vm/proto/pb/sender"
)

// TestGRPCServerInterface verifies that Server implements SenderServer
func TestGRPCServerInterface(t *testing.T) {
	var _ SenderServer = (*Server)(nil)
	var _ senderpb.SenderServer = (*Server)(nil)
}

// TestGRPCClientInterface verifies that grpcClient implements p2p.Sender
func TestGRPCClientInterface(t *testing.T) {
	var _ p2p.Sender = (*grpcClient)(nil)
}
