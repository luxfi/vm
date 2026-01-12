// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/database"

	vmpb "github.com/luxfi/node/proto/pb/vm"
)

var (
	errEnumToError = map[vmpb.Error]error{
		vmpb.Error_ERROR_CLOSED:                     database.ErrClosed,
		vmpb.Error_ERROR_NOT_FOUND:                  database.ErrNotFound,
		vmpb.Error_ERROR_STATE_SYNC_NOT_IMPLEMENTED: block.ErrRemoteVMNotImplemented,
	}
	errorToErrEnum = map[error]vmpb.Error{
		database.ErrClosed:              vmpb.Error_ERROR_CLOSED,
		database.ErrNotFound:            vmpb.Error_ERROR_NOT_FOUND,
		block.ErrRemoteVMNotImplemented: vmpb.Error_ERROR_STATE_SYNC_NOT_IMPLEMENTED,
	}
)

func errorToRPCError(err error) error {
	if _, ok := errorToErrEnum[err]; ok {
		return nil
	}
	return err
}
