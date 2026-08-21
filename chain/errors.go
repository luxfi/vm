// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import (
	"errors"

	"github.com/luxfi/consensus/engine/chain/block"
)

var (
	// ErrRemoteVMNotImplemented is returned when the remote VM is not implemented.
	ErrRemoteVMNotImplemented = errors.New("remote VM not implemented")
	// ErrStateSyncableVMNotImplemented is what a VM returns when it does not sync
	// state. It IS the engine's sentinel rather than a second value spelling the
	// same words, so a VM written against either package returns something the
	// other recognizes and errors.Is answers alike for both.
	ErrStateSyncableVMNotImplemented = block.ErrStateSyncableVMNotImplemented
)
