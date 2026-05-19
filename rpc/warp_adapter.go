//go:build grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	pwarp "github.com/luxfi/proto/p/warp"
	"github.com/luxfi/warp"
)

// protocolWarpSignerAdapter wraps a warp.Signer (from github.com/luxfi/warp)
// and adapts it to protocol/p/warp.Signer interface.
//
// Both interfaces have the same method signature:
//   Sign(msg *UnsignedMessage) ([]byte, error)
//
// However, they reference different *UnsignedMessage types from different packages.
// This adapter converts between them.
type protocolWarpSignerAdapter struct {
	inner warp.Signer
}

// newProtocolWarpSignerAdapter creates an adapter that wraps a warp.Signer
// to satisfy protocol/p/warp.Signer.
func newProtocolWarpSignerAdapter(signer warp.Signer) pwarp.Signer {
	if signer == nil {
		return nil
	}
	return &protocolWarpSignerAdapter{inner: signer}
}

// Sign implements protocol/p/warp.Signer by converting the UnsignedMessage
// from protocol/p/warp to warp format and delegating to the inner signer.
func (a *protocolWarpSignerAdapter) Sign(msg *pwarp.UnsignedMessage) ([]byte, error) {
	// Convert protocol/p/warp.UnsignedMessage to warp.UnsignedMessage
	// Both types have identical fields: NetworkID, SourceChainID, Payload
	innerMsg, err := warp.NewUnsignedMessage(
		msg.NetworkID,
		msg.SourceChainID,
		msg.Payload,
	)
	if err != nil {
		return nil, err
	}
	return a.inner.Sign(innerMsg)
}
