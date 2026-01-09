// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package accel

func init() {
	Register("pure", 0, func(config Config) (Accelerator, error) {
		return NewGoAccelerator(config)
	})
}
