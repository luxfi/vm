// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

// Package quasar provides NTT operations for Ringtail consensus.
// This file provides pure Go CPU implementation when CGO is not available.
// All operations use the luxfi/lattice library which provides optimized
// NTT implementations in pure Go.
package quasar

import (
	"sync"
	"sync/atomic"

	"github.com/luxfi/lattice/v7/ring"
)

// GPUNTTAccelerator provides NTT operations for Ringtail.
// When CGO is disabled, this uses the pure Go lattice library
// which provides optimized CPU-based NTT transforms.
type GPUNTTAccelerator struct {
	enabled  bool
	stats    GPUNTTStats
	statsmu  sync.RWMutex
}

// GPUNTTStats tracks NTT accelerator statistics.
type GPUNTTStats struct {
	Enabled       bool
	Backend       string
	CachedRings   int
	TotalOps      uint64
}

// NewGPUNTTAccelerator creates a new NTT accelerator using pure Go lattice library.
func NewGPUNTTAccelerator() (*GPUNTTAccelerator, error) {
	return &GPUNTTAccelerator{
		enabled: true, // CPU implementation is always available
		stats: GPUNTTStats{
			Enabled: true,
			Backend: "CPU (Pure Go)",
		},
	}, nil
}

// IsEnabled returns true - CPU implementation is always available.
func (g *GPUNTTAccelerator) IsEnabled() bool {
	return true
}

// Backend returns the backend name.
func (g *GPUNTTAccelerator) Backend() string {
	return "CPU (Pure Go lattice)"
}

// NTTForward performs forward NTT on a polynomial using lattice library.
func (g *GPUNTTAccelerator) NTTForward(r *ring.Ring, poly ring.Poly) error {
	r.NTT(poly, poly)
	atomic.AddUint64(&g.stats.TotalOps, 1)
	return nil
}

// NTTInverse performs inverse NTT on a polynomial using lattice library.
func (g *GPUNTTAccelerator) NTTInverse(r *ring.Ring, poly ring.Poly) error {
	r.INTT(poly, poly)
	atomic.AddUint64(&g.stats.TotalOps, 1)
	return nil
}

// BatchNTTForward performs forward NTT on multiple polynomials.
// Uses parallel processing for better performance on multi-core CPUs.
func (g *GPUNTTAccelerator) BatchNTTForward(r *ring.Ring, polys []ring.Poly) error {
	if len(polys) == 0 {
		return nil
	}

	// For small batches, process sequentially
	if len(polys) < 8 {
		for _, poly := range polys {
			r.NTT(poly, poly)
		}
		atomic.AddUint64(&g.stats.TotalOps, uint64(len(polys)))
		return nil
	}

	// For larger batches, use parallel processing
	var wg sync.WaitGroup
	numWorkers := 4
	chunkSize := (len(polys) + numWorkers - 1) / numWorkers

	for i := 0; i < numWorkers; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(polys) {
			end = len(polys)
		}
		if start >= end {
			break
		}

		wg.Add(1)
		go func(batch []ring.Poly) {
			defer wg.Done()
			for _, poly := range batch {
				r.NTT(poly, poly)
			}
		}(polys[start:end])
	}
	wg.Wait()

	atomic.AddUint64(&g.stats.TotalOps, uint64(len(polys)))
	return nil
}

// BatchNTTInverse performs inverse NTT on multiple polynomials.
// Uses parallel processing for better performance on multi-core CPUs.
func (g *GPUNTTAccelerator) BatchNTTInverse(r *ring.Ring, polys []ring.Poly) error {
	if len(polys) == 0 {
		return nil
	}

	// For small batches, process sequentially
	if len(polys) < 8 {
		for _, poly := range polys {
			r.INTT(poly, poly)
		}
		atomic.AddUint64(&g.stats.TotalOps, uint64(len(polys)))
		return nil
	}

	// For larger batches, use parallel processing
	var wg sync.WaitGroup
	numWorkers := 4
	chunkSize := (len(polys) + numWorkers - 1) / numWorkers

	for i := 0; i < numWorkers; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(polys) {
			end = len(polys)
		}
		if start >= end {
			break
		}

		wg.Add(1)
		go func(batch []ring.Poly) {
			defer wg.Done()
			for _, poly := range batch {
				r.INTT(poly, poly)
			}
		}(polys[start:end])
	}
	wg.Wait()

	atomic.AddUint64(&g.stats.TotalOps, uint64(len(polys)))
	return nil
}

// PolyMul performs polynomial multiplication using Barrett reduction.
func (g *GPUNTTAccelerator) PolyMul(r *ring.Ring, a, b, out ring.Poly) error {
	r.MulCoeffsBarrett(a, b, out)
	atomic.AddUint64(&g.stats.TotalOps, 1)
	return nil
}

// ClearCache is a no-op for CPU implementation (no GPU cache).
func (g *GPUNTTAccelerator) ClearCache() {}

// Stats returns current NTT accelerator statistics.
func (g *GPUNTTAccelerator) Stats() GPUNTTStats {
	g.statsmu.RLock()
	defer g.statsmu.RUnlock()
	return GPUNTTStats{
		Enabled:     true,
		Backend:     "CPU (Pure Go lattice)",
		CachedRings: 0,
		TotalOps:    atomic.LoadUint64(&g.stats.TotalOps),
	}
}

// Global accelerator instance
var (
	globalAccelerator     *GPUNTTAccelerator
	globalAcceleratorOnce sync.Once
)

// GetGPUAccelerator returns the global NTT accelerator instance.
func GetGPUAccelerator() (*GPUNTTAccelerator, error) {
	globalAcceleratorOnce.Do(func() {
		globalAccelerator, _ = NewGPUNTTAccelerator()
	})
	return globalAccelerator, nil
}
