// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zvm

import (
	"github.com/luxfi/log"
	"github.com/luxfi/vm/vms"
)

var _ vms.Factory = (*Factory)(nil)

// Factory ...
type Factory struct{}

// New implements vms.Factory
func (f *Factory) New(log.Logger) (interface{}, error) {
	return &VM{}, nil
}
