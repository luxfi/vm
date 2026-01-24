//go:build grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"github.com/luxfi/database"
	vmchain "github.com/luxfi/vm/chain"

	vmpb "github.com/luxfi/node/proto/pb/vm"
)

// Error mappings between Go errors and protobuf (server-only)
var errorToErrEnum = map[error]vmpb.Error{
	database.ErrClosed:                vmpb.Error_ERROR_CLOSED,
	database.ErrNotFound:              vmpb.Error_ERROR_NOT_FOUND,
	vmchain.ErrRemoteVMNotImplemented: vmpb.Error_ERROR_STATE_SYNC_NOT_IMPLEMENTED,
}

func errorToRPCError(err error) error {
	if _, ok := errorToErrEnum[err]; ok {
		return nil
	}
	return err
}
