// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import (
	"context"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/vm/components/state"
)

// TestBlock is a test implementation of Block
type TestBlock struct {
	IDV           ids.ID
	HeightV       uint64
	TimestampV    time.Time
	ParentV       ids.ID
	BytesV        []byte
	StatusV       Status
	ErrV          error
	ShouldVerifyV bool
}

func (b *TestBlock) ID() ids.ID {
	return b.IDV
}

func (b *TestBlock) Height() uint64 {
	return b.HeightV
}

func (b *TestBlock) Timestamp() time.Time {
	return b.TimestampV
}

func (b *TestBlock) Parent() ids.ID {
	return b.ParentV
}

func (b *TestBlock) ParentID() ids.ID {
	return b.ParentV
}

func (b *TestBlock) Bytes() []byte {
	return b.BytesV
}

func (b *TestBlock) Verify(context.Context) error {
	if !b.ShouldVerifyV {
		return b.ErrV
	}
	return nil
}

func (b *TestBlock) Accept(context.Context) error {
	b.StatusV = Accepted
	return b.ErrV
}

func (b *TestBlock) Reject(context.Context) error {
	b.StatusV = Rejected
	return b.ErrV
}

func (b *TestBlock) Status() uint8 {
	return uint8(b.StatusV)
}

func (b *TestBlock) State() state.ReadOnlyChain {
	return nil
}
