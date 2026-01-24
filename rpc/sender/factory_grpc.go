//go:build grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sender

import (
	"github.com/luxfi/p2p"
	senderpb "github.com/luxfi/vm/proto/pb/sender"
)

// NewSenderServer creates a new sender server with the default transport.
// When both transports are available (default build), this uses gRPC.
// Use NewZAPServer explicitly for ZAP transport.
func NewSenderServer(sender p2p.Sender) SenderServer {
	return NewServer(sender)
}

// NewSenderClient creates a new sender client with gRPC transport.
// When both transports are available (default build), this uses gRPC.
// Use ZAP() explicitly for ZAP transport.
func NewSenderClient(client senderpb.SenderClient) p2p.Sender {
	return GRPC(client)
}
