//go:build !grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sender

import (
	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/p2p"
)

// NewSenderServer creates a new sender server with ZAP transport (default).
func NewSenderServer(sender p2p.Sender) SenderServer {
	return NewZAPServer(sender)
}

// NewSenderClient creates a new sender client with ZAP transport (default).
func NewSenderClient(conn *zapwire.Conn) p2p.Sender {
	return ZAP(conn)
}
