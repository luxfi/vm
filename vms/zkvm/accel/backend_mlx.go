// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && (darwin || linux)

package accel

func init() {
	Register("mlx", 100, func(config Config) (Accelerator, error) {
		return NewMLXAccelerator(config)
	})
}
