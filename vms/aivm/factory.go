// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"github.com/luxfi/log"
	"github.com/luxfi/vm/vms"
)

var _ vms.Factory = (*Factory)(nil)

// Factory implements vms.Factory interface for creating AIVM instances
type Factory struct{}

// New creates a new AIVM instance
func (f *Factory) New(log log.Logger) (interface{}, error) {
	return &VM{}, nil
}
