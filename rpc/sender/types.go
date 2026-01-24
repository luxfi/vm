// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sender

import "context"

// SenderServer is a common interface for both gRPC and ZAP sender servers.
// This allows code to work with either transport without build tag complications.
type SenderServer interface {
	// GRPCRegistrar returns the gRPC server implementation if available.
	// Returns nil if this is a ZAP-only server.
	GRPCRegistrar() interface{}

	// ZAPHandler returns the ZAP message handler if available.
	// Returns nil if this is a gRPC-only server.
	ZAPHandler() ZAPHandler
}

// ZAPHandler handles ZAP sender messages.
type ZAPHandler interface {
	// Handle routes a ZAP message to the appropriate handler.
	// The msgType is the ZAP message type identifier.
	Handle(ctx context.Context, msgType uint8, payload []byte) error
}
