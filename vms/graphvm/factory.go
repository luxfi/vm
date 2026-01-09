// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package gvm

import (
	"github.com/luxfi/log"
	"github.com/luxfi/vm/vms"
)

var _ vms.Factory = (*Factory)(nil)

// Factory creates new instances of the Graph VM
type Factory struct{}

// New returns a new instance of the Graph VM
func (f *Factory) New(log.Logger) (interface{}, error) {
	return &VM{}, nil
}
