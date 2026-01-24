//go:build grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dag

import (
	"github.com/luxfi/database"
	dagpb "github.com/luxfi/vm/proto/pb/dag"
)

// Error mappings between protobuf and Go errors
var errEnumToError = map[dagpb.Error]error{
	dagpb.Error_ERROR_CLOSED:    database.ErrClosed,
	dagpb.Error_ERROR_NOT_FOUND: database.ErrNotFound,
}
