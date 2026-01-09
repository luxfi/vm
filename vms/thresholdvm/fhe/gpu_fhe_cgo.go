//go:build cgo

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package fhe provides GPU-accelerated FHE operations for ThresholdVM.
//
// This file provides GPU acceleration for:
//   - NTT forward/inverse transforms (40x speedup on Apple Silicon)
//   - Polynomial multiplication in CKKS scheme
//   - Batch FHE operations for throughput
//
// Architecture:
//
//	luxcpp/lattice (C++ GPU) → lux/lattice/gpu (Go CGO) → ThresholdVM FHE
package fhe

import (
	"fmt"
	"sync"

	"github.com/luxfi/config"
	"github.com/luxfi/lattice/v7/gpu"
	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/log"
)

// GPUFHEAccelerator provides GPU-accelerated FHE operations for ThresholdVM.
// It wraps the lattice/gpu package to accelerate CKKS operations.
type GPUFHEAccelerator struct {
	mu       sync.RWMutex
	contexts map[uint64]*gpu.NTTContext // Q modulus -> NTTContext
	enabled  bool
	logger   log.Logger
	stats    *GPUFHEStats
}

// GPUFHEStats tracks GPU acceleration statistics
type GPUFHEStats struct {
	NTTForwardCalls  uint64
	NTTInverseCalls  uint64
	PolyMulCalls     uint64
	BatchCalls       uint64
	GPUFallbackCalls uint64
	TotalGPUTimeNs   uint64
}

// GPUFHEOptions holds options for creating a GPU FHE accelerator.
type GPUFHEOptions struct {
	// Enabled controls whether GPU acceleration is used
	Enabled bool
	// Backend specifies which GPU backend to use: "auto", "metal", "cuda", "cpu"
	Backend string
}

// NewGPUFHEAccelerator creates a new GPU FHE accelerator for ThresholdVM.
func NewGPUFHEAccelerator(logger log.Logger) (*GPUFHEAccelerator, error) {
	return NewGPUFHEAcceleratorWithOptions(logger, GPUFHEOptions{})
}

// NewGPUFHEAcceleratorWithOptions creates a new GPU FHE accelerator with custom options.
// If options are zero-valued, it uses the global GPU config.
func NewGPUFHEAcceleratorWithOptions(logger log.Logger, opts GPUFHEOptions) (*GPUFHEAccelerator, error) {
	// Get global config if options not specified
	gpuCfg := config.GetGlobalGPUConfig()

	// Determine if GPU should be enabled
	enabled := gpuCfg.Enabled
	if opts.Backend == "cpu" {
		enabled = false
	}

	// Check if GPU is available via libLattice
	// The backend (Metal/CUDA) is auto-detected by libLattice at runtime
	available := gpu.GPUAvailable() && enabled

	if logger != nil {
		if available {
			logger.Info("GPU FHE acceleration enabled",
				"backend", gpu.GetBackend(),
				"configBackend", gpuCfg.Backend)
		} else {
			logger.Warn("GPU FHE acceleration not available, using CPU fallback",
				"gpuConfigEnabled", gpuCfg.Enabled,
				"gpuAvailable", gpu.GPUAvailable())
		}
	}

	return &GPUFHEAccelerator{
		contexts: make(map[uint64]*gpu.NTTContext),
		enabled:  available,
		logger:   logger,
		stats:    &GPUFHEStats{},
	}, nil
}

// IsEnabled returns whether GPU acceleration is available.
func (g *GPUFHEAccelerator) IsEnabled() bool {
	return g.enabled
}

// Backend returns the active GPU backend name.
func (g *GPUFHEAccelerator) Backend() string {
	if !g.enabled {
		return "CPU (GPU not available)"
	}
	return gpu.GetBackend()
}

// Stats returns current GPU statistics.
func (g *GPUFHEAccelerator) Stats() GPUFHEStats {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return *g.stats
}

// getOrCreateContext gets or creates an NTT context for the given parameters.
func (g *GPUFHEAccelerator) getOrCreateContext(N uint32, Q uint64) (*gpu.NTTContext, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	ctx, ok := g.contexts[Q]
	if ok && ctx.N == N {
		return ctx, nil
	}

	newCtx, err := gpu.NewNTTContext(N, Q)
	if err != nil {
		return nil, fmt.Errorf("failed to create NTT context: %w", err)
	}

	g.contexts[Q] = newCtx
	return newCtx, nil
}

// GPUNumberTheoreticTransformer implements ring.NumberTheoreticTransformer
// using GPU acceleration for ThresholdVM FHE operations.
type GPUNumberTheoreticTransformer struct {
	accel    *GPUFHEAccelerator
	N        int
	Q        uint64
	nttTable *ring.NTTTable
	fallback ring.NumberTheoreticTransformer
}

// NewGPUNumberTheoreticTransformer creates a GPU-accelerated NTT transformer.
// This can be used to replace the CPU NTT in lattice/ring operations.
func NewGPUNumberTheoreticTransformer(
	accel *GPUFHEAccelerator,
	subring *ring.SubRing,
	n int,
) ring.NumberTheoreticTransformer {
	return &GPUNumberTheoreticTransformer{
		accel:    accel,
		N:        n,
		Q:        subring.Modulus,
		nttTable: subring.NTTTable,
		fallback: ring.NewNumberTheoreticTransformerStandard(subring, n),
	}
}

// Forward performs GPU-accelerated forward NTT.
func (t *GPUNumberTheoreticTransformer) Forward(p1, p2 []uint64) {
	if !t.accel.enabled || len(p1) < 1024 {
		// Use CPU for small polynomials (GPU overhead not worth it)
		t.fallback.Forward(p1, p2)
		return
	}

	ctx, err := t.accel.getOrCreateContext(uint32(t.N), t.Q)
	if err != nil {
		t.fallback.Forward(p1, p2)
		t.accel.mu.Lock()
		t.accel.stats.GPUFallbackCalls++
		t.accel.mu.Unlock()
		return
	}

	// Copy input to output (NTT is in-place)
	copy(p2, p1)

	// GPU NTT
	batch := [][]uint64{p2}
	result, err := ctx.NTT(batch)
	if err != nil {
		t.fallback.Forward(p1, p2)
		t.accel.mu.Lock()
		t.accel.stats.GPUFallbackCalls++
		t.accel.mu.Unlock()
		return
	}

	// Copy result
	copy(p2, result[0])

	t.accel.mu.Lock()
	t.accel.stats.NTTForwardCalls++
	t.accel.mu.Unlock()
}

// ForwardLazy performs GPU-accelerated forward NTT (lazy reduction).
func (t *GPUNumberTheoreticTransformer) ForwardLazy(p1, p2 []uint64) {
	// GPU NTT always does full reduction, so same as Forward
	t.Forward(p1, p2)
}

// Backward performs GPU-accelerated inverse NTT.
func (t *GPUNumberTheoreticTransformer) Backward(p1, p2 []uint64) {
	if !t.accel.enabled || len(p1) < 1024 {
		t.fallback.Backward(p1, p2)
		return
	}

	ctx, err := t.accel.getOrCreateContext(uint32(t.N), t.Q)
	if err != nil {
		t.fallback.Backward(p1, p2)
		t.accel.mu.Lock()
		t.accel.stats.GPUFallbackCalls++
		t.accel.mu.Unlock()
		return
	}

	// Copy input to output
	copy(p2, p1)

	// GPU INTT
	batch := [][]uint64{p2}
	result, err := ctx.INTT(batch)
	if err != nil {
		t.fallback.Backward(p1, p2)
		t.accel.mu.Lock()
		t.accel.stats.GPUFallbackCalls++
		t.accel.mu.Unlock()
		return
	}

	copy(p2, result[0])

	t.accel.mu.Lock()
	t.accel.stats.NTTInverseCalls++
	t.accel.mu.Unlock()
}

// BackwardLazy performs GPU-accelerated inverse NTT (lazy reduction).
func (t *GPUNumberTheoreticTransformer) BackwardLazy(p1, p2 []uint64) {
	t.Backward(p1, p2)
}

// BatchNTTForward performs forward NTT on multiple polynomials.
// This is the primary use case for GPU acceleration - batch operations.
func (g *GPUFHEAccelerator) BatchNTTForward(r *ring.Ring, polys []ring.Poly) error {
	if len(polys) == 0 {
		return nil
	}

	// Get parameters from ring
	N := r.N()

	// GPU only beneficial for large batches (>64 polys with N>=8192)
	// Otherwise CPU is faster due to data transfer overhead
	if !g.enabled || len(polys) < 64 || N < 8192 {
		for i := range polys {
			r.NTT(polys[i], polys[i])
		}
		return nil
	}

	if len(r.ModuliChain()) == 0 {
		return fmt.Errorf("ring has no moduli")
	}
	Q := r.ModuliChain()[0]

	ctx, err := g.getOrCreateContext(uint32(N), Q)
	if err != nil {
		// Fallback to CPU
		for i := range polys {
			r.NTT(polys[i], polys[i])
		}
		return nil
	}

	// Build batch
	batch := make([][]uint64, len(polys))
	for i, poly := range polys {
		batch[i] = make([]uint64, N)
		if len(poly.Coeffs) > 0 && len(poly.Coeffs[0]) >= N {
			copy(batch[i], poly.Coeffs[0])
		}
	}

	// GPU batch NTT
	results, err := ctx.NTT(batch)
	if err != nil {
		for i := range polys {
			r.NTT(polys[i], polys[i])
		}
		return nil
	}

	// Copy results back
	for i := range polys {
		if len(polys[i].Coeffs) > 0 {
			copy(polys[i].Coeffs[0], results[i])
		}
	}

	g.mu.Lock()
	g.stats.BatchCalls++
	g.mu.Unlock()

	return nil
}

// BatchNTTInverse performs inverse NTT on multiple polynomials.
func (g *GPUFHEAccelerator) BatchNTTInverse(r *ring.Ring, polys []ring.Poly) error {
	if len(polys) == 0 {
		return nil
	}

	if !g.enabled || len(polys) < 4 {
		for i := range polys {
			r.INTT(polys[i], polys[i])
		}
		return nil
	}

	N := r.N()
	if len(r.ModuliChain()) == 0 {
		return fmt.Errorf("ring has no moduli")
	}
	Q := r.ModuliChain()[0]

	ctx, err := g.getOrCreateContext(uint32(N), Q)
	if err != nil {
		for i := range polys {
			r.INTT(polys[i], polys[i])
		}
		return nil
	}

	batch := make([][]uint64, len(polys))
	for i, poly := range polys {
		batch[i] = make([]uint64, N)
		if len(poly.Coeffs) > 0 && len(poly.Coeffs[0]) >= N {
			copy(batch[i], poly.Coeffs[0])
		}
	}

	results, err := ctx.INTT(batch)
	if err != nil {
		for i := range polys {
			r.INTT(polys[i], polys[i])
		}
		return nil
	}

	for i := range polys {
		if len(polys[i].Coeffs) > 0 {
			copy(polys[i].Coeffs[0], results[i])
		}
	}

	g.mu.Lock()
	g.stats.BatchCalls++
	g.mu.Unlock()

	return nil
}

// BatchPolyMul performs polynomial multiplication on batches using GPU.
func (g *GPUFHEAccelerator) BatchPolyMul(r *ring.Ring, a, b, out []ring.Poly) error {
	if len(a) != len(b) || len(a) != len(out) {
		return fmt.Errorf("batch size mismatch")
	}

	if !g.enabled || len(a) < 4 {
		// CPU fallback
		for i := range a {
			r.MulCoeffsBarrett(a[i], b[i], out[i])
		}
		return nil
	}

	N := r.N()
	if len(r.ModuliChain()) == 0 {
		return fmt.Errorf("ring has no moduli")
	}
	Q := r.ModuliChain()[0]

	ctx, err := g.getOrCreateContext(uint32(N), Q)
	if err != nil {
		for i := range a {
			r.MulCoeffsBarrett(a[i], b[i], out[i])
		}
		return nil
	}

	// Build batches
	aBatch := make([][]uint64, len(a))
	bBatch := make([][]uint64, len(b))
	for i := range a {
		aBatch[i] = make([]uint64, N)
		bBatch[i] = make([]uint64, N)
		if len(a[i].Coeffs) > 0 && len(a[i].Coeffs[0]) >= N {
			copy(aBatch[i], a[i].Coeffs[0])
		}
		if len(b[i].Coeffs) > 0 && len(b[i].Coeffs[0]) >= N {
			copy(bBatch[i], b[i].Coeffs[0])
		}
	}

	// GPU polynomial multiplication
	results, err := ctx.PolyMul(aBatch, bBatch)
	if err != nil {
		for i := range a {
			r.MulCoeffsBarrett(a[i], b[i], out[i])
		}
		return nil
	}

	// Copy results
	for i := range out {
		if len(out[i].Coeffs) > 0 {
			copy(out[i].Coeffs[0], results[i])
		}
	}

	g.mu.Lock()
	g.stats.PolyMulCalls++
	g.mu.Unlock()

	return nil
}

// ClearCache clears all cached NTT contexts.
func (g *GPUFHEAccelerator) ClearCache() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.contexts = make(map[uint64]*gpu.NTTContext)
	gpu.ClearCache()
}

// Close releases all GPU resources.
func (g *GPUFHEAccelerator) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()

	for _, ctx := range g.contexts {
		ctx.Close()
	}
	g.contexts = nil
}

// Global GPU accelerator instance (lazily initialized)
var (
	globalGPUFHEAccelerator     *GPUFHEAccelerator
	globalGPUFHEAcceleratorOnce sync.Once
	globalGPUFHEAcceleratorErr  error
)

// GetGPUFHEAccelerator returns the global GPU FHE accelerator instance.
func GetGPUFHEAccelerator() (*GPUFHEAccelerator, error) {
	globalGPUFHEAcceleratorOnce.Do(func() {
		globalGPUFHEAccelerator, globalGPUFHEAcceleratorErr = NewGPUFHEAccelerator(nil)
	})
	return globalGPUFHEAccelerator, globalGPUFHEAcceleratorErr
}
