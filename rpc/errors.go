//go:build grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"github.com/luxfi/database"
	vmchain "github.com/luxfi/vm/chain"

	vmpb "github.com/luxfi/node/proto/pb/vm"
)

// Error mappings between protobuf and Go errors (used by client)
var errEnumToError = map[vmpb.Error]error{
	vmpb.Error_ERROR_CLOSED:                     database.ErrClosed,
	vmpb.Error_ERROR_NOT_FOUND:                  database.ErrNotFound,
	vmpb.Error_ERROR_STATE_SYNC_NOT_IMPLEMENTED: vmchain.ErrRemoteVMNotImplemented,
}
