//go:build !cgo

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package fhe provides FHE operations for ThresholdVM.
// This file provides pure Go CPU implementation when CGO is not available.
// All operations use the luxfi/lattice library which provides optimized
// NTT and polynomial operations in pure Go.
package fhe

import (
	"sync"
	"sync/atomic"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/log"
)

// GPUFHEAccelerator provides FHE operations using pure Go lattice library.
// When CGO is disabled, this uses the CPU-based lattice library which
// provides optimized NTT, polynomial multiplication, and ring operations.
type GPUFHEAccelerator struct {
	stats   *GPUFHEStats
	statsmu sync.RWMutex
}

// GPUFHEStats tracks FHE acceleration statistics
type GPUFHEStats struct {
	NTTForwardCalls  uint64
	NTTInverseCalls  uint64
	PolyMulCalls     uint64
	BatchCalls       uint64
	GPUFallbackCalls uint64
	TotalGPUTimeNs   uint64
}

// NewGPUFHEAccelerator creates a new FHE accelerator using pure Go lattice library.
func NewGPUFHEAccelerator(_ log.Logger) (*GPUFHEAccelerator, error) {
	return &GPUFHEAccelerator{
		stats: &GPUFHEStats{},
	}, nil
}

// IsEnabled returns true - CPU implementation is always available.
func (g *GPUFHEAccelerator) IsEnabled() bool {
	return true
}

// Backend returns the backend name.
func (g *GPUFHEAccelerator) Backend() string {
	return "CPU (Pure Go lattice)"
}

// Stats returns current FHE statistics.
func (g *GPUFHEAccelerator) Stats() GPUFHEStats {
	g.statsmu.RLock()
	defer g.statsmu.RUnlock()
	return *g.stats
}

// BatchNTTForward performs forward NTT on multiple polynomials.
// Uses parallel processing for better performance on multi-core CPUs.
func (g *GPUFHEAccelerator) BatchNTTForward(r *ring.Ring, polys []ring.Poly) error {
	if len(polys) == 0 {
		return nil
	}

	// For small batches, process sequentially
	if len(polys) < 8 {
		for i := range polys {
			r.NTT(polys[i], polys[i])
		}
		atomic.AddUint64(&g.stats.NTTForwardCalls, uint64(len(polys)))
		return nil
	}

	// For larger batches, use parallel processing
	var wg sync.WaitGroup
	numWorkers := 4
	chunkSize := (len(polys) + numWorkers - 1) / numWorkers

	for w := 0; w < numWorkers; w++ {
		start := w * chunkSize
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
			for i := range batch {
				r.NTT(batch[i], batch[i])
			}
		}(polys[start:end])
	}
	wg.Wait()

	atomic.AddUint64(&g.stats.NTTForwardCalls, uint64(len(polys)))
	atomic.AddUint64(&g.stats.BatchCalls, 1)
	return nil
}

// BatchNTTInverse performs inverse NTT on multiple polynomials.
// Uses parallel processing for better performance on multi-core CPUs.
func (g *GPUFHEAccelerator) BatchNTTInverse(r *ring.Ring, polys []ring.Poly) error {
	if len(polys) == 0 {
		return nil
	}

	// For small batches, process sequentially
	if len(polys) < 8 {
		for i := range polys {
			r.INTT(polys[i], polys[i])
		}
		atomic.AddUint64(&g.stats.NTTInverseCalls, uint64(len(polys)))
		return nil
	}

	// For larger batches, use parallel processing
	var wg sync.WaitGroup
	numWorkers := 4
	chunkSize := (len(polys) + numWorkers - 1) / numWorkers

	for w := 0; w < numWorkers; w++ {
		start := w * chunkSize
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
			for i := range batch {
				r.INTT(batch[i], batch[i])
			}
		}(polys[start:end])
	}
	wg.Wait()

	atomic.AddUint64(&g.stats.NTTInverseCalls, uint64(len(polys)))
	atomic.AddUint64(&g.stats.BatchCalls, 1)
	return nil
}

// BatchPolyMul performs polynomial multiplication on batches.
// Uses parallel processing for better performance on multi-core CPUs.
func (g *GPUFHEAccelerator) BatchPolyMul(r *ring.Ring, a, b, out []ring.Poly) error {
	if len(a) == 0 {
		return nil
	}

	// For small batches, process sequentially
	if len(a) < 8 {
		for i := range a {
			r.MulCoeffsBarrett(a[i], b[i], out[i])
		}
		atomic.AddUint64(&g.stats.PolyMulCalls, uint64(len(a)))
		return nil
	}

	// For larger batches, use parallel processing
	var wg sync.WaitGroup
	numWorkers := 4
	chunkSize := (len(a) + numWorkers - 1) / numWorkers

	for w := 0; w < numWorkers; w++ {
		start := w * chunkSize
		end := start + chunkSize
		if end > len(a) {
			end = len(a)
		}
		if start >= end {
			break
		}

		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			for i := s; i < e; i++ {
				r.MulCoeffsBarrett(a[i], b[i], out[i])
			}
		}(start, end)
	}
	wg.Wait()

	atomic.AddUint64(&g.stats.PolyMulCalls, uint64(len(a)))
	atomic.AddUint64(&g.stats.BatchCalls, 1)
	return nil
}

// ClearCache is a no-op for CPU implementation.
func (g *GPUFHEAccelerator) ClearCache() {}

// Close is a no-op for CPU implementation.
func (g *GPUFHEAccelerator) Close() {}

// Global accelerator instance
var (
	globalGPUFHEAccelerator     *GPUFHEAccelerator
	globalGPUFHEAcceleratorOnce sync.Once
)

// GetGPUFHEAccelerator returns the global FHE accelerator instance.
func GetGPUFHEAccelerator() (*GPUFHEAccelerator, error) {
	globalGPUFHEAcceleratorOnce.Do(func() {
		globalGPUFHEAccelerator, _ = NewGPUFHEAccelerator(nil)
	})
	return globalGPUFHEAccelerator, nil
}

// GPUNumberTheoreticTransformer provides NTT operations using lattice library.
// This wraps the standard lattice NTT transformer.
type GPUNumberTheoreticTransformer struct {
	fallback ring.NumberTheoreticTransformer
}

// NewGPUNumberTheoreticTransformer creates a CPU-based NTT transformer.
func NewGPUNumberTheoreticTransformer(
	_ *GPUFHEAccelerator,
	subring *ring.SubRing,
	n int,
) ring.NumberTheoreticTransformer {
	return ring.NewNumberTheoreticTransformerStandard(subring, n)
}
