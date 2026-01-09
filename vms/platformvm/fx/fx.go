// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package fx provides type aliases for github.com/luxfi/vm/platformvm/fx.
// This maintains backwards compatibility while consolidating types in vm/platformvm/fx.
package fx

import (
	vmfx "github.com/luxfi/vm/platformvm/fx"
)

// Type aliases for backwards compatibility
type (
	Fx                  = vmfx.Fx
	Owner               = vmfx.Owner
	Owned               = vmfx.Owned
	OutputOwnersWrapper = vmfx.OutputOwnersWrapper
)
