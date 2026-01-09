// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package accel provides hardware acceleration for ZK operations.
//
// Two backends:
//   - Pure Go: Always available, portable
//   - MLX: CGO path with Metal/CUDA/CPU fallback via luxcpp
//
// With CGO_ENABLED=0: Pure Go
// With CGO_ENABLED=1: MLX (auto-selects Metal, CUDA, or optimized CPU)
package accel

import (
	"errors"
	"fmt"
)

// Backend represents the compute backend for ZK acceleration
type Backend string

const (
	BackendGo   Backend = "pure" // Pure Go implementation
	BackendMLX  Backend = "mlx"  // MLX: Metal/CUDA/CPU via luxcpp
	BackendFPGA Backend = "fpga" // FPGA acceleration (optional build tag)
)

var (
	ErrProofGeneration   = errors.New("proof generation failed")
	ErrProofVerification = errors.New("proof verification failed")
	ErrNTTComputation    = errors.New("NTT computation failed")
	ErrMSMComputation    = errors.New("MSM computation failed")
	ErrHashComputation   = errors.New("hash computation failed")
	ErrFHEOperation      = errors.New("FHE operation failed")
)

// Config for ZK accelerator
type Config struct {
	Backend       Backend `json:"backend"`
	Device        string  `json:"device"`
	MaxBatchSize  int     `json:"maxBatchSize"`
	NumThreads    int     `json:"numThreads"`
	EnableFHE     bool    `json:"enableFHE"`
	ProofSystem   string  `json:"proofSystem"`   // groth16, plonk, stark
	SecurityLevel int     `json:"securityLevel"` // 128, 192, 256
}

// DefaultConfig returns default accelerator configuration
func DefaultConfig() Config {
	return Config{
		MaxBatchSize:  1024,
		NumThreads:    0, // 0 = auto-detect
		EnableFHE:     false,
		ProofSystem:   "groth16",
		SecurityLevel: 128,
	}
}

// FieldElement represents an element in the finite field
type FieldElement struct {
	Limbs [4]uint64 // 256-bit field element
}

// Point represents a point on an elliptic curve
type Point struct {
	X, Y FieldElement
	Z    FieldElement // Projective coordinate (optional)
}

// Polynomial represents a polynomial over the field
type Polynomial struct {
	Coeffs []FieldElement
	Degree int
}

// Proof represents a ZK proof
type Proof struct {
	System     string // groth16, plonk, stark
	ProofBytes []byte
	PublicIO   []FieldElement
	Metadata   map[string]interface{}
}

// VerifyingKey represents a verification key
type VerifyingKey struct {
	System   string
	KeyBytes []byte
}

// ProvingKey represents a proving key
type ProvingKey struct {
	System   string
	KeyBytes []byte
}

// Ciphertext represents an FHE ciphertext
type Ciphertext struct {
	Data       []byte
	Scheme     string // TFHE, BFV, CKKS
	NoiseLevel uint16
}

// NTTConfig configuration for Number Theoretic Transform
type NTTConfig struct {
	LogN    int    // log2 of polynomial degree
	Modulus uint64 // Field modulus
	Forward bool   // Forward or inverse NTT
	InPlace bool   // Modify input in place
}

// MSMConfig configuration for Multi-Scalar Multiplication
type MSMConfig struct {
	NumPoints  int
	ScalarBits int
	WindowSize int
	UsePrecomp bool
}

// HashConfig configuration for hash operations
type HashConfig struct {
	Algorithm string // poseidon, poseidon2, keccak256, blake3
	Rate      int    // Sponge rate
	Capacity  int    // Sponge capacity
}

// Accelerator interface for ZK operations
type Accelerator interface {
	// Info
	Backend() Backend
	Device() string
	IsGPUAvailable() bool
	Capabilities() Capabilities
	Close() error

	// Core ZK Operations
	NTT(input []FieldElement, config NTTConfig) ([]FieldElement, error)
	INTT(input []FieldElement, config NTTConfig) ([]FieldElement, error)
	MSM(points []Point, scalars []FieldElement, config MSMConfig) (Point, error)
	Hash(input []FieldElement, config HashConfig) (FieldElement, error)
	BatchHash(inputs [][]FieldElement, config HashConfig) ([]FieldElement, error)

	// Proof Operations
	GenerateProof(witness []FieldElement, publicInput []FieldElement, pk *ProvingKey) (*Proof, error)
	VerifyProof(proof *Proof, publicInput []FieldElement, vk *VerifyingKey) (bool, error)
	AggregateProofs(proofs []*Proof) (*Proof, error)

	// FHE Operations (optional, only if EnableFHE)
	FHEAdd(a, b *Ciphertext) (*Ciphertext, error)
	FHESub(a, b *Ciphertext) (*Ciphertext, error)
	FHEMul(a, b *Ciphertext) (*Ciphertext, error)
	FHEBootstrap(ct *Ciphertext) (*Ciphertext, error)

	// Benchmarking
	Benchmark(ops int) BenchmarkResult
}

// Capabilities describes what the accelerator supports
type Capabilities struct {
	SupportsNTT      bool
	SupportsMSM      bool
	SupportsGroth16  bool
	SupportsPLONK    bool
	SupportsSTARK    bool
	SupportsFHE      bool
	MaxPolynomialDeg int
	MaxMSMPoints     int
	MaxBatchSize     int
	ParallelProofs   int
}

// BenchmarkResult contains benchmark results
type BenchmarkResult struct {
	Backend       Backend
	Device        string
	NTTOpsPerSec  float64
	MSMOpsPerSec  float64
	HashOpsPerSec float64
	ProofsPerSec  float64
	LatencyNs     int64
}

// String returns a string representation of the benchmark
func (b BenchmarkResult) String() string {
	return fmt.Sprintf(
		"Backend: %s, Device: %s, NTT: %.2f ops/s, MSM: %.2f ops/s, Hash: %.2f ops/s, Proofs: %.2f/s, Latency: %dns",
		b.Backend, b.Device, b.NTTOpsPerSec, b.MSMOpsPerSec, b.HashOpsPerSec, b.ProofsPerSec, b.LatencyNs,
	)
}
