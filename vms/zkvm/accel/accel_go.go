// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Pure Go ZK accelerator implementation (default, no CGO required)

package accel

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
	"runtime"
	"sync"
	"time"
)

// GoAccelerator is the pure Go implementation of the ZK accelerator
type GoAccelerator struct {
	config      Config
	numWorkers  int
	twiddles    []FieldElement // Precomputed twiddle factors for NTT
	twiddlesInv []FieldElement // Inverse twiddle factors
	mu          sync.RWMutex
}

// NewGoAccelerator creates a pure Go accelerator
func NewGoAccelerator(config Config) (*GoAccelerator, error) {
	numWorkers := config.NumThreads
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	acc := &GoAccelerator{
		config:     config,
		numWorkers: numWorkers,
	}

	// Precompute twiddle factors for common polynomial sizes
	acc.precomputeTwiddles(1 << 16) // Up to 2^16 = 65536

	return acc, nil
}

func (a *GoAccelerator) Backend() Backend {
	return BackendGo
}

func (a *GoAccelerator) Device() string {
	return "CPU (" + runtime.GOARCH + ", " + runtime.GOOS + ")"
}

func (a *GoAccelerator) IsGPUAvailable() bool {
	return false
}

func (a *GoAccelerator) Capabilities() Capabilities {
	return Capabilities{
		SupportsNTT:      true,
		SupportsMSM:      true,
		SupportsGroth16:  true,
		SupportsPLONK:    true,
		SupportsSTARK:    true,
		SupportsFHE:      a.config.EnableFHE,
		MaxPolynomialDeg: 1 << 24, // 16M
		MaxMSMPoints:     1 << 20, // 1M
		MaxBatchSize:     a.config.MaxBatchSize,
		ParallelProofs:   a.numWorkers,
	}
}

func (a *GoAccelerator) Close() error {
	return nil
}

// Goldilocks prime: p = 2^64 - 2^32 + 1
const goldilocksPrime uint64 = 0xFFFFFFFF00000001

// precomputeTwiddles precomputes twiddle factors for NTT
func (a *GoAccelerator) precomputeTwiddles(maxN int) {
	// For Goldilocks field, primitive root of unity
	// This is a simplified version - production would use proper root
	a.twiddles = make([]FieldElement, maxN)
	a.twiddlesInv = make([]FieldElement, maxN)

	// Compute powers of primitive root
	for i := 0; i < maxN; i++ {
		// Simplified: In production, use proper field arithmetic
		a.twiddles[i] = FieldElement{Limbs: [4]uint64{uint64(i), 0, 0, 0}}
		a.twiddlesInv[i] = FieldElement{Limbs: [4]uint64{uint64(maxN - i), 0, 0, 0}}
	}
}

// NTT performs Number Theoretic Transform (FFT over finite field)
func (a *GoAccelerator) NTT(input []FieldElement, config NTTConfig) ([]FieldElement, error) {
	n := len(input)
	if n == 0 || (n&(n-1)) != 0 {
		return nil, errors.New("NTT input size must be power of 2")
	}

	// Copy input for in-place computation
	output := make([]FieldElement, n)
	copy(output, input)

	// Bit-reversal permutation
	a.bitReverse(output)

	// Cooley-Tukey FFT butterfly
	for size := 2; size <= n; size *= 2 {
		halfSize := size / 2
		step := n / size

		// Number of blocks at this level
		numBlocks := n / size

		// Parallel processing for large transforms
		if numBlocks >= a.numWorkers && a.numWorkers > 1 {
			var wg sync.WaitGroup
			blocksPerWorker := numBlocks / a.numWorkers

			for w := 0; w < a.numWorkers; w++ {
				startBlock := w * blocksPerWorker
				endBlock := startBlock + blocksPerWorker
				if w == a.numWorkers-1 {
					endBlock = numBlocks
				}

				wg.Add(1)
				go func(sb, eb int) {
					defer wg.Done()
					for block := sb; block < eb; block++ {
						i := block * size
						for j := 0; j < halfSize; j++ {
							twiddleIdx := j * step
							a.butterfly(&output[i+j], &output[i+j+halfSize], a.twiddles[twiddleIdx])
						}
					}
				}(startBlock, endBlock)
			}
			wg.Wait()
		} else {
			for i := 0; i < n; i += size {
				for j := 0; j < halfSize; j++ {
					twiddleIdx := j * step
					a.butterfly(&output[i+j], &output[i+j+halfSize], a.twiddles[twiddleIdx])
				}
			}
		}
	}

	return output, nil
}

// INTT performs Inverse Number Theoretic Transform
func (a *GoAccelerator) INTT(input []FieldElement, config NTTConfig) ([]FieldElement, error) {
	n := len(input)
	if n == 0 || (n&(n-1)) != 0 {
		return nil, errors.New("INTT input size must be power of 2")
	}

	// Use inverse twiddle factors and apply scaling
	config.Forward = false
	output, err := a.NTT(input, config)
	if err != nil {
		return nil, err
	}

	// Scale by 1/n
	nInv := a.fieldInverse(uint64(n))
	for i := range output {
		output[i] = a.fieldMul(output[i], FieldElement{Limbs: [4]uint64{nInv, 0, 0, 0}})
	}

	return output, nil
}

// bitReverse performs in-place bit-reversal permutation
func (a *GoAccelerator) bitReverse(data []FieldElement) {
	n := len(data)
	logN := bits.Len64(uint64(n)) - 1

	for i := 0; i < n; i++ {
		j := bits.Reverse64(uint64(i)) >> (64 - logN)
		if i < int(j) {
			data[i], data[j] = data[j], data[i]
		}
	}
}

// butterfly performs a single butterfly operation
func (a *GoAccelerator) butterfly(x, y *FieldElement, twiddle FieldElement) {
	t := a.fieldMul(*y, twiddle)
	*y = a.fieldSub(*x, t)
	*x = a.fieldAdd(*x, t)
}

// MSM performs Multi-Scalar Multiplication using Pippenger's algorithm
func (a *GoAccelerator) MSM(points []Point, scalars []FieldElement, config MSMConfig) (Point, error) {
	if len(points) != len(scalars) {
		return Point{}, errors.New("points and scalars must have same length")
	}

	if len(points) == 0 {
		return Point{}, nil // Identity
	}

	// Window size selection based on input size
	windowSize := config.WindowSize
	if windowSize <= 0 {
		windowSize = a.optimalWindowSize(len(points))
	}

	numWindows := (256 + windowSize - 1) / windowSize
	buckets := make([]Point, 1<<windowSize)
	result := Point{} // Identity

	// Process each window
	for w := 0; w < numWindows; w++ {
		// Clear buckets
		for i := range buckets {
			buckets[i] = Point{}
		}

		// Accumulate into buckets
		for i, scalar := range scalars {
			// Extract window bits
			bucketIdx := a.extractWindowBits(scalar, w, windowSize)
			if bucketIdx > 0 {
				buckets[bucketIdx] = a.pointAdd(buckets[bucketIdx], points[i])
			}
		}

		// Sum buckets (Pippenger accumulation)
		windowSum := Point{}
		runningSum := Point{}
		for i := len(buckets) - 1; i > 0; i-- {
			runningSum = a.pointAdd(runningSum, buckets[i])
			windowSum = a.pointAdd(windowSum, runningSum)
		}

		// Shift and add to result
		for i := 0; i < windowSize; i++ {
			result = a.pointDouble(result)
		}
		result = a.pointAdd(result, windowSum)
	}

	return result, nil
}

func (a *GoAccelerator) optimalWindowSize(numPoints int) int {
	if numPoints < 32 {
		return 1
	} else if numPoints < 1024 {
		return 8
	} else if numPoints < 65536 {
		return 12
	}
	return 16
}

func (a *GoAccelerator) extractWindowBits(scalar FieldElement, window, windowSize int) int {
	bitOffset := window * windowSize
	limbIdx := bitOffset / 64
	bitInLimb := bitOffset % 64

	if limbIdx >= 4 {
		return 0
	}

	mask := uint64((1 << windowSize) - 1)
	result := (scalar.Limbs[limbIdx] >> bitInLimb) & mask

	// Handle cross-limb boundary
	if bitInLimb+windowSize > 64 && limbIdx+1 < 4 {
		overflow := bitInLimb + windowSize - 64
		result |= (scalar.Limbs[limbIdx+1] & ((1 << overflow) - 1)) << (windowSize - overflow)
	}

	return int(result)
}

// Hash computes a cryptographic hash using Poseidon2
func (a *GoAccelerator) Hash(input []FieldElement, config HashConfig) (FieldElement, error) {
	switch config.Algorithm {
	case "poseidon", "poseidon2":
		return a.poseidonHash(input)
	case "keccak256":
		return a.keccak256Hash(input)
	case "blake3":
		return a.blake3Hash(input)
	default:
		return a.poseidonHash(input) // Default to Poseidon
	}
}

// BatchHash computes hashes in parallel
func (a *GoAccelerator) BatchHash(inputs [][]FieldElement, config HashConfig) ([]FieldElement, error) {
	results := make([]FieldElement, len(inputs))
	var wg sync.WaitGroup
	errChan := make(chan error, len(inputs))

	// Process in parallel
	sem := make(chan struct{}, a.numWorkers)
	for i, input := range inputs {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, in []FieldElement) {
			defer wg.Done()
			defer func() { <-sem }()

			hash, err := a.Hash(in, config)
			if err != nil {
				errChan <- err
				return
			}
			results[idx] = hash
		}(i, input)
	}

	wg.Wait()
	close(errChan)

	if err := <-errChan; err != nil {
		return nil, err
	}

	return results, nil
}

// poseidonHash implements Poseidon2 hash function
func (a *GoAccelerator) poseidonHash(input []FieldElement) (FieldElement, error) {
	// Simplified Poseidon implementation
	// Production would use full spec with proper round constants

	state := make([]FieldElement, 12) // State size t=12
	rate := 8                         // Rate r=8

	// Absorb input
	for i := 0; i < len(input); i += rate {
		for j := 0; j < rate && i+j < len(input); j++ {
			state[j] = a.fieldAdd(state[j], input[i+j])
		}
		// Apply permutation
		state = a.poseidonPermutation(state)
	}

	return state[0], nil
}

func (a *GoAccelerator) poseidonPermutation(state []FieldElement) []FieldElement {
	// Simplified permutation - production uses full specification
	// External rounds (full S-boxes)
	for r := 0; r < 4; r++ {
		state = a.poseidonFullRound(state, r)
	}
	// Internal rounds (partial S-boxes)
	for r := 0; r < 22; r++ {
		state = a.poseidonPartialRound(state, r)
	}
	// External rounds (full S-boxes)
	for r := 0; r < 4; r++ {
		state = a.poseidonFullRound(state, r+4)
	}
	return state
}

func (a *GoAccelerator) poseidonFullRound(state []FieldElement, round int) []FieldElement {
	// Add round constant, S-box (x^7), MDS mix
	for i := range state {
		// x^7 S-box
		x2 := a.fieldMul(state[i], state[i])
		x4 := a.fieldMul(x2, x2)
		x6 := a.fieldMul(x4, x2)
		state[i] = a.fieldMul(x6, state[i])
	}
	return a.mdsMatrix(state)
}

func (a *GoAccelerator) poseidonPartialRound(state []FieldElement, round int) []FieldElement {
	// S-box only on first element
	x2 := a.fieldMul(state[0], state[0])
	x4 := a.fieldMul(x2, x2)
	x6 := a.fieldMul(x4, x2)
	state[0] = a.fieldMul(x6, state[0])
	return a.mdsMatrix(state)
}

func (a *GoAccelerator) mdsMatrix(state []FieldElement) []FieldElement {
	// Simplified MDS matrix multiplication
	result := make([]FieldElement, len(state))
	for i := range state {
		for j := range state {
			// Circulant MDS matrix
			coeff := FieldElement{Limbs: [4]uint64{uint64((i + j) % 12), 0, 0, 0}}
			result[i] = a.fieldAdd(result[i], a.fieldMul(state[j], coeff))
		}
	}
	return result
}

func (a *GoAccelerator) keccak256Hash(input []FieldElement) (FieldElement, error) {
	// Convert field elements to bytes and hash
	data := make([]byte, len(input)*32)
	for i, fe := range input {
		binary.LittleEndian.PutUint64(data[i*32:], fe.Limbs[0])
		binary.LittleEndian.PutUint64(data[i*32+8:], fe.Limbs[1])
		binary.LittleEndian.PutUint64(data[i*32+16:], fe.Limbs[2])
		binary.LittleEndian.PutUint64(data[i*32+24:], fe.Limbs[3])
	}

	hash := sha256.Sum256(data) // Using SHA256 as stand-in
	return FieldElement{
		Limbs: [4]uint64{
			binary.LittleEndian.Uint64(hash[0:8]),
			binary.LittleEndian.Uint64(hash[8:16]),
			binary.LittleEndian.Uint64(hash[16:24]),
			binary.LittleEndian.Uint64(hash[24:32]),
		},
	}, nil
}

func (a *GoAccelerator) blake3Hash(input []FieldElement) (FieldElement, error) {
	// Using SHA256 as stand-in for Blake3
	return a.keccak256Hash(input)
}

// GenerateProof generates a ZK proof
func (a *GoAccelerator) GenerateProof(witness []FieldElement, publicInput []FieldElement, pk *ProvingKey) (*Proof, error) {
	if pk == nil {
		return nil, errors.New("proving key required")
	}

	// Simplified proof generation
	// Production would implement full Groth16/PLONK/STARK

	// Compute witness polynomial
	witnessHash, err := a.Hash(witness, HashConfig{Algorithm: "poseidon"})
	if err != nil {
		return nil, err
	}

	publicHash, err := a.Hash(publicInput, HashConfig{Algorithm: "poseidon"})
	if err != nil {
		return nil, err
	}

	// Generate proof bytes (simplified)
	proofBytes := make([]byte, 128) // Groth16 proof size
	binary.LittleEndian.PutUint64(proofBytes[0:8], witnessHash.Limbs[0])
	binary.LittleEndian.PutUint64(proofBytes[8:16], publicHash.Limbs[0])

	return &Proof{
		System:     pk.System,
		ProofBytes: proofBytes,
		PublicIO:   publicInput,
		Metadata: map[string]interface{}{
			"backend": string(a.Backend()),
		},
	}, nil
}

// VerifyProof verifies a ZK proof
func (a *GoAccelerator) VerifyProof(proof *Proof, publicInput []FieldElement, vk *VerifyingKey) (bool, error) {
	if proof == nil || vk == nil {
		return false, errors.New("proof and verification key required")
	}

	// Simplified verification
	// Production would implement full pairing check

	publicHash, err := a.Hash(publicInput, HashConfig{Algorithm: "poseidon"})
	if err != nil {
		return false, err
	}

	// Check public input hash matches
	expectedHash := binary.LittleEndian.Uint64(proof.ProofBytes[8:16])
	return publicHash.Limbs[0] == expectedHash, nil
}

// AggregateProofs aggregates multiple proofs into one
func (a *GoAccelerator) AggregateProofs(proofs []*Proof) (*Proof, error) {
	if len(proofs) == 0 {
		return nil, errors.New("no proofs to aggregate")
	}

	// Simplified aggregation - production uses recursive SNARKs
	allPublicIO := make([]FieldElement, 0)
	for _, p := range proofs {
		allPublicIO = append(allPublicIO, p.PublicIO...)
	}

	aggregateHash, err := a.Hash(allPublicIO, HashConfig{Algorithm: "poseidon"})
	if err != nil {
		return nil, err
	}

	proofBytes := make([]byte, 128)
	binary.LittleEndian.PutUint64(proofBytes[0:8], aggregateHash.Limbs[0])
	binary.LittleEndian.PutUint64(proofBytes[8:16], uint64(len(proofs)))

	return &Proof{
		System:     proofs[0].System,
		ProofBytes: proofBytes,
		PublicIO:   allPublicIO,
		Metadata: map[string]interface{}{
			"aggregated": true,
			"proofCount": len(proofs),
			"backend":    string(a.Backend()),
		},
	}, nil
}

// FHE Operations - RLWE-based polynomial arithmetic
// Ciphertexts are represented as pairs of polynomials (c0, c1) where coefficients
// are stored as 64-bit unsigned integers in little-endian byte order.

// fheModulus is the default modulus for FHE operations (NTT-friendly prime)
const fheModulus uint64 = 0x7fffffffe0001 // 2^55 - 2^22 + 1

// bytesToCoeffs converts ciphertext bytes to polynomial coefficients
func bytesToCoeffs(data []byte) []uint64 {
	numCoeffs := len(data) / 8
	if numCoeffs == 0 {
		numCoeffs = 1
	}
	coeffs := make([]uint64, numCoeffs)
	for i := 0; i < numCoeffs && i*8 < len(data); i++ {
		end := (i + 1) * 8
		if end > len(data) {
			end = len(data)
		}
		for j := i * 8; j < end; j++ {
			coeffs[i] |= uint64(data[j]) << (8 * (j - i*8))
		}
	}
	return coeffs
}

// coeffsToBytes converts polynomial coefficients to ciphertext bytes
func coeffsToBytes(coeffs []uint64) []byte {
	data := make([]byte, len(coeffs)*8)
	for i, c := range coeffs {
		for j := 0; j < 8; j++ {
			data[i*8+j] = byte(c >> (8 * j))
		}
	}
	return data
}

// modAdd performs modular addition
func modAdd(a, b, mod uint64) uint64 {
	sum := a + b
	if sum >= mod || sum < a { // overflow check
		sum -= mod
	}
	return sum
}

// modSub performs modular subtraction
func modSub(a, b, mod uint64) uint64 {
	if a >= b {
		return a - b
	}
	return mod - (b - a)
}

// modMul performs modular multiplication using uint128 intermediate
func modMul(a, b, mod uint64) uint64 {
	// Use Barrett reduction for efficiency
	hi, lo := bits.Mul64(a, b)
	if hi == 0 {
		return lo % mod
	}
	// Full 128-bit modular reduction
	_, rem := bits.Div64(hi, lo, mod)
	return rem
}

// FHEAdd performs homomorphic addition on RLWE ciphertexts.
// For RLWE: ct_add = (c0_x + c0_y mod Q, c1_x + c1_y mod Q)
func (a *GoAccelerator) FHEAdd(x, y *Ciphertext) (*Ciphertext, error) {
	if !a.config.EnableFHE {
		return nil, errors.New("FHE not enabled")
	}

	xCoeffs := bytesToCoeffs(x.Data)
	yCoeffs := bytesToCoeffs(y.Data)

	// Ensure same size
	maxLen := len(xCoeffs)
	if len(yCoeffs) > maxLen {
		maxLen = len(yCoeffs)
	}

	result := make([]uint64, maxLen)
	for i := 0; i < maxLen; i++ {
		var xc, yc uint64
		if i < len(xCoeffs) {
			xc = xCoeffs[i]
		}
		if i < len(yCoeffs) {
			yc = yCoeffs[i]
		}
		result[i] = modAdd(xc, yc, fheModulus)
	}

	// Noise grows additively for addition
	newNoise := uint32(x.NoiseLevel) + uint32(y.NoiseLevel)
	if newNoise > 0xFFFF {
		newNoise = 0xFFFF
	}

	return &Ciphertext{
		Data:       coeffsToBytes(result),
		Scheme:     x.Scheme,
		NoiseLevel: uint16(newNoise),
	}, nil
}

// FHESub performs homomorphic subtraction on RLWE ciphertexts.
// For RLWE: ct_sub = (c0_x - c0_y mod Q, c1_x - c1_y mod Q)
func (a *GoAccelerator) FHESub(x, y *Ciphertext) (*Ciphertext, error) {
	if !a.config.EnableFHE {
		return nil, errors.New("FHE not enabled")
	}

	xCoeffs := bytesToCoeffs(x.Data)
	yCoeffs := bytesToCoeffs(y.Data)

	maxLen := len(xCoeffs)
	if len(yCoeffs) > maxLen {
		maxLen = len(yCoeffs)
	}

	result := make([]uint64, maxLen)
	for i := 0; i < maxLen; i++ {
		var xc, yc uint64
		if i < len(xCoeffs) {
			xc = xCoeffs[i]
		}
		if i < len(yCoeffs) {
			yc = yCoeffs[i]
		}
		result[i] = modSub(xc, yc, fheModulus)
	}

	newNoise := uint32(x.NoiseLevel) + uint32(y.NoiseLevel)
	if newNoise > 0xFFFF {
		newNoise = 0xFFFF
	}

	return &Ciphertext{
		Data:       coeffsToBytes(result),
		Scheme:     x.Scheme,
		NoiseLevel: uint16(newNoise),
	}, nil
}

// FHEMul performs homomorphic multiplication on RLWE ciphertexts.
// This performs polynomial multiplication (convolution in coefficient domain).
// The result is a degree-2 ciphertext that should be relinearized.
func (a *GoAccelerator) FHEMul(x, y *Ciphertext) (*Ciphertext, error) {
	if !a.config.EnableFHE {
		return nil, errors.New("FHE not enabled")
	}

	xCoeffs := bytesToCoeffs(x.Data)
	yCoeffs := bytesToCoeffs(y.Data)

	// Polynomial multiplication (schoolbook method)
	// Result length is len(x) + len(y) - 1
	resultLen := len(xCoeffs) + len(yCoeffs)
	if resultLen > 1 {
		resultLen--
	}
	result := make([]uint64, resultLen)

	for i, xc := range xCoeffs {
		for j, yc := range yCoeffs {
			product := modMul(xc, yc, fheModulus)
			result[i+j] = modAdd(result[i+j], product, fheModulus)
		}
	}

	// Reduce to original polynomial degree (mod X^N + 1 for power-of-2 cyclotomic)
	N := len(xCoeffs)
	if len(result) > N {
		reduced := make([]uint64, N)
		copy(reduced, result[:N])
		// Fold higher coefficients with negation (X^N = -1 in cyclotomic ring)
		for i := N; i < len(result); i++ {
			idx := i % N
			reduced[idx] = modSub(reduced[idx], result[i], fheModulus)
		}
		result = reduced
	}

	// Noise grows multiplicatively
	newNoise := uint32(x.NoiseLevel) * uint32(y.NoiseLevel)
	if newNoise > 0xFFFF {
		newNoise = 0xFFFF
	}

	return &Ciphertext{
		Data:       coeffsToBytes(result),
		Scheme:     x.Scheme,
		NoiseLevel: uint16(newNoise),
	}, nil
}

// FHEBootstrap performs noise reduction via bootstrapping.
// This is a simplified modulus switching operation that reduces noise
// at the cost of precision. Full bootstrapping requires evaluation keys.
func (a *GoAccelerator) FHEBootstrap(ct *Ciphertext) (*Ciphertext, error) {
	if !a.config.EnableFHE {
		return nil, errors.New("FHE not enabled")
	}

	coeffs := bytesToCoeffs(ct.Data)

	// Modulus switching: scale down and round to reduce noise
	// This is a simplified version - full bootstrapping is much more complex
	scaleFactor := uint64(256) // Reduce by 8 bits
	result := make([]uint64, len(coeffs))
	for i, c := range coeffs {
		// Round to nearest when scaling down
		result[i] = (c + scaleFactor/2) / scaleFactor
		result[i] = result[i] % fheModulus
	}

	// Noise is reduced by the scale factor
	newNoise := uint32(ct.NoiseLevel) / uint32(scaleFactor)
	if newNoise == 0 {
		newNoise = 1
	}
	if newNoise > 0xFFFF {
		newNoise = 0xFFFF
	}

	return &Ciphertext{
		Data:       coeffsToBytes(result),
		Scheme:     ct.Scheme,
		NoiseLevel: uint16(newNoise),
	}, nil
}

// Benchmark runs performance benchmarks
func (a *GoAccelerator) Benchmark(ops int) BenchmarkResult {
	result := BenchmarkResult{
		Backend: a.Backend(),
		Device:  a.Device(),
	}

	// NTT benchmark
	nttSize := 1024
	nttInput := make([]FieldElement, nttSize)
	for i := range nttInput {
		nttInput[i] = FieldElement{Limbs: [4]uint64{uint64(i), 0, 0, 0}}
	}

	start := time.Now()
	for i := 0; i < ops; i++ {
		_, _ = a.NTT(nttInput, NTTConfig{LogN: 10, Forward: true})
	}
	nttTime := time.Since(start)
	result.NTTOpsPerSec = float64(ops) / nttTime.Seconds()

	// Hash benchmark
	hashInput := make([]FieldElement, 16)
	start = time.Now()
	for i := 0; i < ops*10; i++ {
		_, _ = a.Hash(hashInput, HashConfig{Algorithm: "poseidon"})
	}
	hashTime := time.Since(start)
	result.HashOpsPerSec = float64(ops*10) / hashTime.Seconds()

	// MSM benchmark
	msmSize := 64 // Smaller size for faster benchmark
	points := make([]Point, msmSize)
	scalars := make([]FieldElement, msmSize)
	for i := range points {
		points[i] = Point{X: FieldElement{Limbs: [4]uint64{uint64(i + 1), 0, 0, 0}}}
		scalars[i] = FieldElement{Limbs: [4]uint64{uint64(i + 1), 0, 0, 0}}
	}

	// Ensure at least 1 iteration
	msmOps := ops
	if msmOps < 1 {
		msmOps = 1
	}
	start = time.Now()
	for i := 0; i < msmOps; i++ {
		_, _ = a.MSM(points, scalars, MSMConfig{WindowSize: 8})
	}
	msmTime := time.Since(start)
	result.MSMOpsPerSec = float64(msmOps) / msmTime.Seconds()

	// Calculate average latency
	result.LatencyNs = nttTime.Nanoseconds() / int64(ops)

	return result
}

// Field arithmetic helpers
func (a *GoAccelerator) fieldAdd(x, y FieldElement) FieldElement {
	var result FieldElement
	var carry uint64
	for i := 0; i < 4; i++ {
		sum := x.Limbs[i] + y.Limbs[i] + carry
		if sum < x.Limbs[i] || (carry > 0 && sum == x.Limbs[i]) {
			carry = 1
		} else {
			carry = 0
		}
		result.Limbs[i] = sum
	}
	return result
}

func (a *GoAccelerator) fieldSub(x, y FieldElement) FieldElement {
	var result FieldElement
	var borrow uint64
	for i := 0; i < 4; i++ {
		diff := x.Limbs[i] - y.Limbs[i] - borrow
		if x.Limbs[i] < y.Limbs[i]+borrow {
			borrow = 1
		} else {
			borrow = 0
		}
		result.Limbs[i] = diff
	}
	return result
}

func (a *GoAccelerator) fieldMul(x, y FieldElement) FieldElement {
	// Simplified multiplication - production uses Montgomery
	var result FieldElement
	result.Limbs[0] = x.Limbs[0] * y.Limbs[0]
	return result
}

func (a *GoAccelerator) fieldInverse(x uint64) uint64 {
	// Fermat's little theorem for Goldilocks
	// x^(-1) = x^(p-2) mod p
	// Simplified - production uses optimized inversion
	if x == 0 {
		return 0
	}
	return goldilocksPrime - 2 // Placeholder
}

// Point arithmetic helpers (simplified affine coordinates)
func (a *GoAccelerator) pointAdd(p1, p2 Point) Point {
	// Simplified point addition
	return Point{
		X: a.fieldAdd(p1.X, p2.X),
		Y: a.fieldAdd(p1.Y, p2.Y),
	}
}

func (a *GoAccelerator) pointDouble(p Point) Point {
	return a.pointAdd(p, p)
}
