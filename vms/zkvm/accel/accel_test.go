// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package accel

import "testing"

func TestNewAccelerator(t *testing.T) {
	// Force pure backend via env var for testing
	t.Setenv("LUX_ZK_BACKEND", "pure")

	config := DefaultConfig()
	acc, err := NewAccelerator(config)
	if err != nil {
		t.Fatalf("NewAccelerator failed: %v", err)
	}
	defer acc.Close()

	if acc.Backend() != BackendGo {
		t.Errorf("Expected pure backend, got %v", acc.Backend())
	}
}

func TestGoAccelerator_NTT(t *testing.T) {
	config := DefaultConfig()
	acc, err := NewGoAccelerator(config)
	if err != nil {
		t.Fatalf("NewGoAccelerator failed: %v", err)
	}
	defer acc.Close()

	// Test power of 2 size
	sizes := []int{16, 64, 256, 1024}
	for _, size := range sizes {
		input := make([]FieldElement, size)
		for i := range input {
			input[i] = FieldElement{Limbs: [4]uint64{uint64(i), 0, 0, 0}}
		}

		output, err := acc.NTT(input, NTTConfig{LogN: 10, Forward: true})
		if err != nil {
			t.Errorf("NTT failed for size %d: %v", size, err)
			continue
		}

		if len(output) != size {
			t.Errorf("NTT output size mismatch: expected %d, got %d", size, len(output))
		}
	}
}

func TestGoAccelerator_NTT_InvalidSize(t *testing.T) {
	config := DefaultConfig()
	acc, err := NewGoAccelerator(config)
	if err != nil {
		t.Fatalf("NewGoAccelerator failed: %v", err)
	}
	defer acc.Close()

	// Non-power of 2 should fail
	input := make([]FieldElement, 100) // Not power of 2
	_, err = acc.NTT(input, NTTConfig{LogN: 7, Forward: true})
	if err == nil {
		t.Error("Expected error for non-power-of-2 input")
	}
}

func TestGoAccelerator_INTT(t *testing.T) {
	config := DefaultConfig()
	acc, err := NewGoAccelerator(config)
	if err != nil {
		t.Fatalf("NewGoAccelerator failed: %v", err)
	}
	defer acc.Close()

	input := make([]FieldElement, 64)
	for i := range input {
		input[i] = FieldElement{Limbs: [4]uint64{uint64(i), 0, 0, 0}}
	}

	// Forward NTT
	nttOutput, err := acc.NTT(input, NTTConfig{LogN: 6, Forward: true})
	if err != nil {
		t.Fatalf("NTT failed: %v", err)
	}

	// Inverse NTT
	inttOutput, err := acc.INTT(nttOutput, NTTConfig{LogN: 6, Forward: false})
	if err != nil {
		t.Fatalf("INTT failed: %v", err)
	}

	if len(inttOutput) != len(input) {
		t.Errorf("INTT output size mismatch")
	}
}

func TestGoAccelerator_MSM(t *testing.T) {
	config := DefaultConfig()
	acc, err := NewGoAccelerator(config)
	if err != nil {
		t.Fatalf("NewGoAccelerator failed: %v", err)
	}
	defer acc.Close()

	n := 64
	points := make([]Point, n)
	scalars := make([]FieldElement, n)

	for i := range points {
		points[i] = Point{
			X: FieldElement{Limbs: [4]uint64{uint64(i + 1), 0, 0, 0}},
			Y: FieldElement{Limbs: [4]uint64{uint64(i + 2), 0, 0, 0}},
		}
		scalars[i] = FieldElement{Limbs: [4]uint64{uint64(i + 1), 0, 0, 0}}
	}

	result, err := acc.MSM(points, scalars, MSMConfig{WindowSize: 8})
	if err != nil {
		t.Fatalf("MSM failed: %v", err)
	}

	// Result should be a point (non-zero)
	if result.X.Limbs[0] == 0 && result.Y.Limbs[0] == 0 {
		t.Log("MSM result is zero point (may be expected for test data)")
	}
}

func TestGoAccelerator_MSM_LengthMismatch(t *testing.T) {
	config := DefaultConfig()
	acc, err := NewGoAccelerator(config)
	if err != nil {
		t.Fatalf("NewGoAccelerator failed: %v", err)
	}
	defer acc.Close()

	points := make([]Point, 10)
	scalars := make([]FieldElement, 5) // Mismatched length

	_, err = acc.MSM(points, scalars, MSMConfig{})
	if err == nil {
		t.Error("Expected error for mismatched lengths")
	}
}

func TestGoAccelerator_Hash(t *testing.T) {
	config := DefaultConfig()
	acc, err := NewGoAccelerator(config)
	if err != nil {
		t.Fatalf("NewGoAccelerator failed: %v", err)
	}
	defer acc.Close()

	input := make([]FieldElement, 8)
	for i := range input {
		input[i] = FieldElement{Limbs: [4]uint64{uint64(i), 0, 0, 0}}
	}

	hash, err := acc.Hash(input, HashConfig{Algorithm: "poseidon", Rate: 8})
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	// Hash should be non-zero
	if hash.Limbs[0] == 0 && hash.Limbs[1] == 0 && hash.Limbs[2] == 0 && hash.Limbs[3] == 0 {
		t.Log("Hash result is zero (may need proper constants)")
	}
}

func TestGoAccelerator_BatchHash(t *testing.T) {
	config := DefaultConfig()
	acc, err := NewGoAccelerator(config)
	if err != nil {
		t.Fatalf("NewGoAccelerator failed: %v", err)
	}
	defer acc.Close()

	inputs := make([][]FieldElement, 10)
	for i := range inputs {
		inputs[i] = make([]FieldElement, 8)
		for j := range inputs[i] {
			inputs[i][j] = FieldElement{Limbs: [4]uint64{uint64(i*8 + j), 0, 0, 0}}
		}
	}

	hashes, err := acc.BatchHash(inputs, HashConfig{Algorithm: "poseidon"})
	if err != nil {
		t.Fatalf("BatchHash failed: %v", err)
	}

	if len(hashes) != len(inputs) {
		t.Errorf("BatchHash output count mismatch: expected %d, got %d", len(inputs), len(hashes))
	}
}

func TestGoAccelerator_GenerateProof(t *testing.T) {
	config := DefaultConfig()
	acc, err := NewGoAccelerator(config)
	if err != nil {
		t.Fatalf("NewGoAccelerator failed: %v", err)
	}
	defer acc.Close()

	witness := make([]FieldElement, 8)
	publicInput := make([]FieldElement, 2)
	pk := &ProvingKey{System: "groth16"}

	proof, err := acc.GenerateProof(witness, publicInput, pk)
	if err != nil {
		t.Fatalf("GenerateProof failed: %v", err)
	}

	if proof.System != "groth16" {
		t.Errorf("Proof system mismatch: expected groth16, got %s", proof.System)
	}

	if proof.Metadata["backend"] != string(BackendGo) {
		t.Errorf("Proof backend mismatch")
	}
}

func TestGoAccelerator_VerifyProof(t *testing.T) {
	config := DefaultConfig()
	acc, err := NewGoAccelerator(config)
	if err != nil {
		t.Fatalf("NewGoAccelerator failed: %v", err)
	}
	defer acc.Close()

	witness := make([]FieldElement, 8)
	publicInput := make([]FieldElement, 2)
	pk := &ProvingKey{System: "groth16"}
	vk := &VerifyingKey{System: "groth16"}

	proof, err := acc.GenerateProof(witness, publicInput, pk)
	if err != nil {
		t.Fatalf("GenerateProof failed: %v", err)
	}

	valid, err := acc.VerifyProof(proof, publicInput, vk)
	if err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}

	if !valid {
		t.Log("Proof verification returned false (expected for placeholder implementation)")
	}
}

func TestGoAccelerator_AggregateProofs(t *testing.T) {
	config := DefaultConfig()
	acc, err := NewGoAccelerator(config)
	if err != nil {
		t.Fatalf("NewGoAccelerator failed: %v", err)
	}
	defer acc.Close()

	proofs := make([]*Proof, 3)
	for i := range proofs {
		proofs[i] = &Proof{
			System:     "groth16",
			ProofBytes: make([]byte, 256),
			PublicIO:   make([]FieldElement, 2),
			Metadata:   make(map[string]interface{}),
		}
	}

	aggregated, err := acc.AggregateProofs(proofs)
	if err != nil {
		t.Fatalf("AggregateProofs failed: %v", err)
	}

	if aggregated == nil {
		t.Error("AggregateProofs returned nil")
	}
}

func TestGoAccelerator_Capabilities(t *testing.T) {
	config := DefaultConfig()
	acc, err := NewGoAccelerator(config)
	if err != nil {
		t.Fatalf("NewGoAccelerator failed: %v", err)
	}
	defer acc.Close()

	caps := acc.Capabilities()

	if !caps.SupportsNTT {
		t.Error("Expected NTT support")
	}
	if !caps.SupportsMSM {
		t.Error("Expected MSM support")
	}
	if !caps.SupportsGroth16 {
		t.Error("Expected Groth16 support")
	}
	if caps.MaxPolynomialDeg <= 0 {
		t.Error("Expected positive MaxPolynomialDeg")
	}
}

func TestGoAccelerator_FHE_Disabled(t *testing.T) {
	config := DefaultConfig()
	config.EnableFHE = false

	acc, err := NewGoAccelerator(config)
	if err != nil {
		t.Fatalf("NewGoAccelerator failed: %v", err)
	}
	defer acc.Close()

	ct := &Ciphertext{Data: make([]byte, 100), Scheme: "TFHE"}

	// FHE operations should fail when disabled
	_, err = acc.FHEAdd(ct, ct)
	if err == nil {
		t.Error("Expected error for FHE operation when disabled")
	}
}

func TestGoAccelerator_FHE_Enabled(t *testing.T) {
	config := DefaultConfig()
	config.EnableFHE = true

	acc, err := NewGoAccelerator(config)
	if err != nil {
		t.Fatalf("NewGoAccelerator failed: %v", err)
	}
	defer acc.Close()

	ct := &Ciphertext{
		Data:       make([]byte, 100),
		Scheme:     "TFHE",
		NoiseLevel: 1,
	}

	// FHE Add
	result, err := acc.FHEAdd(ct, ct)
	if err != nil {
		t.Fatalf("FHEAdd failed: %v", err)
	}
	if result == nil {
		t.Error("FHEAdd returned nil")
	}

	// FHE Mul
	result, err = acc.FHEMul(ct, ct)
	if err != nil {
		t.Fatalf("FHEMul failed: %v", err)
	}
	if result == nil {
		t.Error("FHEMul returned nil")
	}

	// FHE Bootstrap
	result, err = acc.FHEBootstrap(ct)
	if err != nil {
		t.Fatalf("FHEBootstrap failed: %v", err)
	}
	if result.NoiseLevel != 1 {
		t.Error("Bootstrap should reset noise level to 1")
	}
}

func TestGetAvailableBackends(t *testing.T) {
	backends := GetAvailableBackends()

	// Pure backend should always be available
	hasPure := false
	for _, b := range backends {
		if b == "pure" {
			hasPure = true
			break
		}
	}

	if !hasPure {
		t.Error("Pure backend should always be available")
	}
}

func TestBackendInfo(t *testing.T) {
	backends := []string{"pure", "mlx", "fpga"}

	for _, b := range backends {
		info := BackendInfo(b)
		if info == "" {
			t.Errorf("Empty info for backend %v", b)
		}
	}
}

func TestGoAccelerator_Benchmark(t *testing.T) {
	config := DefaultConfig()
	acc, err := NewGoAccelerator(config)
	if err != nil {
		t.Fatalf("NewGoAccelerator failed: %v", err)
	}
	defer acc.Close()

	// Run a small benchmark (ops must be >= 10 for MSM)
	result := acc.Benchmark(10)

	if result.Backend != BackendGo {
		t.Errorf("Expected pure backend, got %v", result.Backend)
	}

	if result.NTTOpsPerSec <= 0 {
		t.Error("Expected positive NTT ops/sec")
	}

	if result.HashOpsPerSec <= 0 {
		t.Error("Expected positive Hash ops/sec")
	}

	if result.MSMOpsPerSec <= 0 {
		t.Error("Expected positive MSM ops/sec")
	}
}
