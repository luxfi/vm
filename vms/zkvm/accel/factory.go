// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package accel provides hardware acceleration for ZK operations.
//
// Backend selection uses a priority-based registry:
//   - Pure Go (priority 0): Always available, no dependencies
//   - MLX (priority 100): CGO path - Metal/CUDA/CPU fallback via luxcpp
//   - FPGA (priority 200): Optional, requires fpga build tag
//
// With CGO_ENABLED=0: Pure Go backend
// With CGO_ENABLED=1: MLX backend (highest priority, handles GPU/CPU internally)
package accel

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

var (
	ErrNoBackend = errors.New("no accelerator backend registered")
)

// backendCtor holds a backend constructor with its priority
type backendCtor struct {
	name     string
	priority int
	new      func(Config) (Accelerator, error)
}

var (
	ctors   []backendCtor
	ctorsMu sync.RWMutex
)

// Register adds a backend constructor with the given priority.
// Higher priority backends are preferred. Called from init() in backend files.
func Register(name string, priority int, ctor func(Config) (Accelerator, error)) {
	ctorsMu.Lock()
	defer ctorsMu.Unlock()
	ctors = append(ctors, backendCtor{name: name, priority: priority, new: ctor})
}

// NewAccelerator creates the best available accelerator.
// Uses LUX_ZK_BACKEND env var to force a specific backend, otherwise picks highest priority.
func NewAccelerator(config Config) (Accelerator, error) {
	ctorsMu.RLock()
	defer ctorsMu.RUnlock()

	if len(ctors) == 0 {
		return nil, ErrNoBackend
	}

	// Sort by priority descending
	sorted := make([]backendCtor, len(ctors))
	copy(sorted, ctors)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].priority > sorted[j].priority
	})

	// Check for environment override
	if envBackend := os.Getenv("LUX_ZK_BACKEND"); envBackend != "" {
		envBackend = strings.ToLower(envBackend)
		for _, c := range sorted {
			if strings.ToLower(c.name) == envBackend {
				return c.new(config)
			}
		}
		return nil, fmt.Errorf("requested backend %q not available", envBackend)
	}

	// Use highest priority backend
	return sorted[0].new(config)
}

// GetAvailableBackends returns names of all registered backends, sorted by priority
func GetAvailableBackends() []string {
	ctorsMu.RLock()
	defer ctorsMu.RUnlock()

	sorted := make([]backendCtor, len(ctors))
	copy(sorted, ctors)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].priority > sorted[j].priority
	})

	names := make([]string, len(sorted))
	for i, c := range sorted {
		names[i] = c.name
	}
	return names
}

// BackendInfo returns description of a backend
func BackendInfo(name string) string {
	switch strings.ToLower(name) {
	case "pure", "go":
		return "Pure Go - portable, no dependencies"
	case "mlx":
		return "MLX - GPU acceleration via Metal/CUDA with CPU fallback"
	case "fpga":
		return "FPGA - hardware acceleration (AMD Versal, AWS F2, Intel Stratix)"
	default:
		return "Unknown backend"
	}
}
