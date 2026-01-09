// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package xsvm

import (
	"context"

	"github.com/luxfi/vm/vms/platformvm/warp"
	luxWarp "github.com/luxfi/warp"
)

var _ luxWarp.Verifier = (*xsvmVerifier)(nil)

// xsvmVerifier allows signing all warp messages
type xsvmVerifier struct{}

func (xsvmVerifier) Verify(context.Context, *luxWarp.UnsignedMessage, []byte) error {
	return nil
}

// xsvmWarpSignerAdapter adapts internal warp.Signer to luxWarp.Signer (external warp)
type xsvmWarpSignerAdapter struct {
	signer interface {
		Sign(*warp.UnsignedMessage) ([]byte, error)
	}
}

// Sign implements luxWarp.Signer interface
func (a *xsvmWarpSignerAdapter) Sign(msg *luxWarp.UnsignedMessage) ([]byte, error) {
	// Convert external warp message (luxWarp) to internal warp message (platformvm/warp)
	// msg.SourceChainID is already ids.ID type
	internalMsg, err := warp.NewUnsignedMessage(msg.NetworkID, msg.SourceChainID, msg.Payload)
	if err != nil {
		return nil, err
	}
	return a.signer.Sign(internalMsg)
}
