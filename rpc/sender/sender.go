// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package sender provides p2p.Sender implementations over ZAP and gRPC transports.
//
// ZAP is the default transport with zero-copy serialization and minimal overhead.
// gRPC support can be added with the grpc build tag for testing compatibility.
//
// Build tags:
//
//	go build                  # ZAP only (default, production)
//	go build -tags=grpc       # gRPC support (for testing/compatibility)
//
// Usage:
//
//	// ZAP transport (default)
//	s := sender.ZAP(zapConn)
//
//	// gRPC transport (requires -tags=grpc)
//	s := sender.GRPC(senderpb.NewSenderClient(grpcConn))
//
// Both return p2p.Sender with identical behavior, just different wire protocol.
// ZAP provides ~5-10x faster serialization and ~30-50% lower CPU usage.
package sender
