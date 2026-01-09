// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package xsvm

import (
	"github.com/luxfi/log"
	"github.com/luxfi/vm/vms"
)

var _ vms.Factory = (*Factory)(nil)

type Factory struct{}

func (*Factory) New(log.Logger) (interface{}, error) {
	return &VM{}, nil
}
