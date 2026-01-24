// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import "errors"

var (
	// ErrRemoteVMNotImplemented is returned when the remote VM is not implemented.
	ErrRemoteVMNotImplemented = errors.New("remote VM not implemented")
	// ErrStateSyncableVMNotImplemented is returned when state syncable VM is not implemented.
	ErrStateSyncableVMNotImplemented = errors.New("state syncable VM not implemented")
)
