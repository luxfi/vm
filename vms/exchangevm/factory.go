// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package exchangevm

import (
	"github.com/luxfi/log"
	"github.com/luxfi/vm/vms"
	"github.com/luxfi/vm/vms/exchangevm/config"
)

var _ vms.Factory = (*Factory)(nil)

type Factory struct {
	config.Config
}

func (f *Factory) New(log.Logger) (interface{}, error) {
	return &VM{Config: f.Config}, nil
}
