// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

// Package quasar provides GPU-accelerated NTT operations for Ringtail consensus.
// This bridges the lux/lattice/gpu package to enable GPU acceleration of lattice
// operations in the Ringtail threshold signature protocol.
//
// GPU acceleration provides 40x+ speedup for NTT operations on Apple Silicon
// and NVIDIA GPUs via MLX (which handles Metal/CUDA/CPU fallback automatically).
//
// Architecture:
//
//	luxcpp/lattice (C++ GPU)  →  lux/lattice/gpu (Go CGO)  →  Quasar consensus
//
// This enables consistent GPU acceleration across:
//   - Ringtail threshold signatures
//   - ML-DSA post-quantum signatures
//   - FHE operations (via luxcpp/fhe which reuses luxcpp/lattice)
package quasar

import (
	"fmt"
	"sync"

	"github.com/luxfi/config"
	"github.com/luxfi/lattice/v7/gpu"
	"github.com/luxfi/lattice/v7/ring"
)

// GPUNTTAccelerator provides GPU-accelerated NTT operations for Ringtail.
// It wraps the lux/lattice/gpu package which uses MLX for Metal/CUDA/CPU backend.
type GPUNTTAccelerator struct {
	mu       sync.RWMutex
	contexts map[uint64]*gpu.NTTContext // Q modulus -> NTTContext
	enabled  bool
}

// GPUNTTOptions holds options for creating a GPU NTT accelerator.
type GPUNTTOptions struct {
	// Enabled controls whether GPU acceleration is used
	Enabled bool
	// Backend specifies which GPU backend to use: "auto", "metal", "cuda", "cpu"
	Backend string
	// DeviceIndex specifies which GPU device to use
	DeviceIndex int
}

// NewGPUNTTAccelerator creates a new GPU NTT accelerator.
// It auto-detects available GPU backends (Metal on macOS, CUDA on Linux).
func NewGPUNTTAccelerator() (*GPUNTTAccelerator, error) {
	return NewGPUNTTAcceleratorWithOptions(GPUNTTOptions{})
}

// NewGPUNTTAcceleratorWithOptions creates a new GPU NTT accelerator with custom options.
// If options are zero-valued, it uses the global GPU config.
func NewGPUNTTAcceleratorWithOptions(opts GPUNTTOptions) (*GPUNTTAccelerator, error) {
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

	return &GPUNTTAccelerator{
		contexts: make(map[uint64]*gpu.NTTContext),
		enabled:  available,
	}, nil
}

// IsEnabled returns whether GPU acceleration is available.
func (g *GPUNTTAccelerator) IsEnabled() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.enabled
}

// Backend returns the name of the active GPU backend.
func (g *GPUNTTAccelerator) Backend() string {
	if !g.enabled {
		return "CPU (GPU not available)"
	}
	return gpu.GetBackend()
}

// getOrCreateContext gets or creates an NTT context for the given ring parameters.
func (g *GPUNTTAccelerator) getOrCreateContext(r *ring.Ring) (*gpu.NTTContext, error) {
	// Get N and Q from ring
	N := uint32(r.N())
	if len(r.ModuliChain()) == 0 {
		return nil, fmt.Errorf("ring has no moduli")
	}
	Q := r.ModuliChain()[0]

	g.mu.Lock()
	defer g.mu.Unlock()

	// Check cache
	ctx, ok := g.contexts[Q]
	if ok && ctx.N == N {
		return ctx, nil
	}

	// Create new context
	newCtx, err := gpu.NewNTTContext(N, Q)
	if err != nil {
		return nil, fmt.Errorf("failed to create NTT context: %w", err)
	}

	g.contexts[Q] = newCtx
	return newCtx, nil
}

// NTTForward performs forward NTT on a polynomial using GPU acceleration.
// Falls back to CPU if GPU is not available.
func (g *GPUNTTAccelerator) NTTForward(r *ring.Ring, poly ring.Poly) error {
	if !g.enabled {
		// Fall back to lattice library's NTT
		r.NTT(poly, poly)
		return nil
	}

	ctx, err := g.getOrCreateContext(r)
	if err != nil {
		// Fall back to CPU
		r.NTT(poly, poly)
		return nil
	}

	// Convert poly to uint64 slice for GPU
	N := r.N()
	data := make([]uint64, N)
	coeffs := poly.Coeffs
	if len(coeffs) == 0 || len(coeffs[0]) < N {
		r.NTT(poly, poly)
		return nil
	}
	copy(data, coeffs[0])

	// Batch of 1 polynomial
	batch := [][]uint64{data}

	// GPU NTT
	result, err := ctx.NTT(batch)
	if err != nil {
		// Fall back to CPU
		r.NTT(poly, poly)
		return nil
	}

	// Copy result back
	copy(coeffs[0], result[0])
	return nil
}

// NTTInverse performs inverse NTT on a polynomial using GPU acceleration.
// Falls back to CPU if GPU is not available.
func (g *GPUNTTAccelerator) NTTInverse(r *ring.Ring, poly ring.Poly) error {
	if !g.enabled {
		// Fall back to lattice library's INTT
		r.INTT(poly, poly)
		return nil
	}

	ctx, err := g.getOrCreateContext(r)
	if err != nil {
		// Fall back to CPU
		r.INTT(poly, poly)
		return nil
	}

	// Convert poly to uint64 slice for GPU
	N := r.N()
	data := make([]uint64, N)
	coeffs := poly.Coeffs
	if len(coeffs) == 0 || len(coeffs[0]) < N {
		r.INTT(poly, poly)
		return nil
	}
	copy(data, coeffs[0])

	// Batch of 1 polynomial
	batch := [][]uint64{data}

	// GPU INTT
	result, err := ctx.INTT(batch)
	if err != nil {
		// Fall back to CPU
		r.INTT(poly, poly)
		return nil
	}

	// Copy result back
	copy(coeffs[0], result[0])
	return nil
}

// BatchNTTForward performs forward NTT on multiple polynomials in parallel.
// This is the primary use case for GPU acceleration - batch operations.
func (g *GPUNTTAccelerator) BatchNTTForward(r *ring.Ring, polys []ring.Poly) error {
	if len(polys) == 0 {
		return nil
	}

	if !g.enabled || len(polys) < 4 {
		// Fall back to CPU for small batches (GPU overhead not worth it)
		for i := range polys {
			r.NTT(polys[i], polys[i])
		}
		return nil
	}

	ctx, err := g.getOrCreateContext(r)
	if err != nil {
		// Fall back to CPU
		for i := range polys {
			r.NTT(polys[i], polys[i])
		}
		return nil
	}

	N := r.N()
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
		// Fall back to CPU
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

	return nil
}

// BatchNTTInverse performs inverse NTT on multiple polynomials in parallel.
func (g *GPUNTTAccelerator) BatchNTTInverse(r *ring.Ring, polys []ring.Poly) error {
	if len(polys) == 0 {
		return nil
	}

	if !g.enabled || len(polys) < 4 {
		// Fall back to CPU for small batches
		for i := range polys {
			r.INTT(polys[i], polys[i])
		}
		return nil
	}

	ctx, err := g.getOrCreateContext(r)
	if err != nil {
		// Fall back to CPU
		for i := range polys {
			r.INTT(polys[i], polys[i])
		}
		return nil
	}

	N := r.N()
	batch := make([][]uint64, len(polys))

	for i, poly := range polys {
		batch[i] = make([]uint64, N)
		if len(poly.Coeffs) > 0 && len(poly.Coeffs[0]) >= N {
			copy(batch[i], poly.Coeffs[0])
		}
	}

	// GPU batch INTT
	results, err := ctx.INTT(batch)
	if err != nil {
		// Fall back to CPU
		for i := range polys {
			r.INTT(polys[i], polys[i])
		}
		return nil
	}

	// Copy results back
	for i := range polys {
		if len(polys[i].Coeffs) > 0 {
			copy(polys[i].Coeffs[0], results[i])
		}
	}

	return nil
}

// PolyMul performs polynomial multiplication using GPU-accelerated NTT.
// This multiplies polynomials a and b, storing result in out.
func (g *GPUNTTAccelerator) PolyMul(r *ring.Ring, a, b, out ring.Poly) error {
	if !g.enabled {
		// Fall back to CPU
		r.MulCoeffsBarrett(a, b, out)
		return nil
	}

	ctx, err := g.getOrCreateContext(r)
	if err != nil {
		// Fall back to CPU
		r.MulCoeffsBarrett(a, b, out)
		return nil
	}

	N := r.N()

	// Extract coefficients
	aData := make([]uint64, N)
	bData := make([]uint64, N)

	if len(a.Coeffs) > 0 && len(a.Coeffs[0]) >= N {
		copy(aData, a.Coeffs[0])
	}
	if len(b.Coeffs) > 0 && len(b.Coeffs[0]) >= N {
		copy(bData, b.Coeffs[0])
	}

	// GPU polynomial multiplication
	result, err := ctx.PolyMul([][]uint64{aData}, [][]uint64{bData})
	if err != nil {
		// Fall back to CPU
		r.MulCoeffsBarrett(a, b, out)
		return nil
	}

	// Copy result back
	if len(out.Coeffs) > 0 {
		copy(out.Coeffs[0], result[0])
	}

	return nil
}

// ClearCache clears the GPU NTT context cache.
func (g *GPUNTTAccelerator) ClearCache() {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.contexts = make(map[uint64]*gpu.NTTContext)
	gpu.ClearCache()
}

// Stats returns GPU accelerator statistics.
type GPUNTTStats struct {
	Enabled      bool
	Backend      string
	CachedModuli int
	GPUAvailable bool
}

// Stats returns current GPU NTT accelerator statistics.
func (g *GPUNTTAccelerator) Stats() GPUNTTStats {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return GPUNTTStats{
		Enabled:      g.enabled,
		Backend:      g.Backend(),
		CachedModuli: len(g.contexts),
		GPUAvailable: gpu.GPUAvailable(),
	}
}

// Global GPU accelerator instance (lazily initialized)
var (
	globalGPUAccelerator     *GPUNTTAccelerator
	globalGPUAcceleratorOnce sync.Once
	globalGPUAcceleratorErr  error
)

// GetGPUAccelerator returns the global GPU NTT accelerator instance.
// The accelerator is lazily initialized on first call.
func GetGPUAccelerator() (*GPUNTTAccelerator, error) {
	globalGPUAcceleratorOnce.Do(func() {
		globalGPUAccelerator, globalGPUAcceleratorErr = NewGPUNTTAccelerator()
	})
	return globalGPUAccelerator, globalGPUAcceleratorErr
}
