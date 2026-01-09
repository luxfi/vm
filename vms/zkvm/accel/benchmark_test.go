// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package accel

import "testing"

func BenchmarkGoAccelerator_NTT_1K(b *testing.B) {
	config := DefaultConfig()
	acc, _ := NewGoAccelerator(config)
	defer acc.Close()

	input := make([]FieldElement, 1024)
	for i := range input {
		input[i] = FieldElement{Limbs: [4]uint64{uint64(i), 0, 0, 0}}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = acc.NTT(input, NTTConfig{LogN: 10, Forward: true})
	}
}

func BenchmarkGoAccelerator_NTT_16K(b *testing.B) {
	config := DefaultConfig()
	acc, _ := NewGoAccelerator(config)
	defer acc.Close()

	input := make([]FieldElement, 16*1024)
	for i := range input {
		input[i] = FieldElement{Limbs: [4]uint64{uint64(i), 0, 0, 0}}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = acc.NTT(input, NTTConfig{LogN: 14, Forward: true})
	}
}

func BenchmarkGoAccelerator_NTT_64K(b *testing.B) {
	config := DefaultConfig()
	acc, _ := NewGoAccelerator(config)
	defer acc.Close()

	input := make([]FieldElement, 64*1024)
	for i := range input {
		input[i] = FieldElement{Limbs: [4]uint64{uint64(i), 0, 0, 0}}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = acc.NTT(input, NTTConfig{LogN: 16, Forward: true})
	}
}

func BenchmarkGoAccelerator_MSM_256(b *testing.B) {
	config := DefaultConfig()
	acc, _ := NewGoAccelerator(config)
	defer acc.Close()

	n := 256
	points := make([]Point, n)
	scalars := make([]FieldElement, n)
	for i := range points {
		points[i] = Point{X: FieldElement{Limbs: [4]uint64{uint64(i), 0, 0, 0}}}
		scalars[i] = FieldElement{Limbs: [4]uint64{uint64(i * 2), 0, 0, 0}}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = acc.MSM(points, scalars, MSMConfig{WindowSize: 8})
	}
}

func BenchmarkGoAccelerator_MSM_1K(b *testing.B) {
	config := DefaultConfig()
	acc, _ := NewGoAccelerator(config)
	defer acc.Close()

	n := 1024
	points := make([]Point, n)
	scalars := make([]FieldElement, n)
	for i := range points {
		points[i] = Point{X: FieldElement{Limbs: [4]uint64{uint64(i), 0, 0, 0}}}
		scalars[i] = FieldElement{Limbs: [4]uint64{uint64(i * 2), 0, 0, 0}}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = acc.MSM(points, scalars, MSMConfig{WindowSize: 10})
	}
}

func BenchmarkGoAccelerator_MSM_4K(b *testing.B) {
	config := DefaultConfig()
	acc, _ := NewGoAccelerator(config)
	defer acc.Close()

	n := 4096
	points := make([]Point, n)
	scalars := make([]FieldElement, n)
	for i := range points {
		points[i] = Point{X: FieldElement{Limbs: [4]uint64{uint64(i), 0, 0, 0}}}
		scalars[i] = FieldElement{Limbs: [4]uint64{uint64(i * 2), 0, 0, 0}}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = acc.MSM(points, scalars, MSMConfig{WindowSize: 12})
	}
}

func BenchmarkGoAccelerator_Hash_8(b *testing.B) {
	config := DefaultConfig()
	acc, _ := NewGoAccelerator(config)
	defer acc.Close()

	input := make([]FieldElement, 8)
	for i := range input {
		input[i] = FieldElement{Limbs: [4]uint64{uint64(i), 0, 0, 0}}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = acc.Hash(input, HashConfig{Algorithm: "poseidon", Rate: 8})
	}
}

func BenchmarkGoAccelerator_Hash_64(b *testing.B) {
	config := DefaultConfig()
	acc, _ := NewGoAccelerator(config)
	defer acc.Close()

	input := make([]FieldElement, 64)
	for i := range input {
		input[i] = FieldElement{Limbs: [4]uint64{uint64(i), 0, 0, 0}}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = acc.Hash(input, HashConfig{Algorithm: "poseidon", Rate: 8})
	}
}

func BenchmarkGoAccelerator_Hash_256(b *testing.B) {
	config := DefaultConfig()
	acc, _ := NewGoAccelerator(config)
	defer acc.Close()

	input := make([]FieldElement, 256)
	for i := range input {
		input[i] = FieldElement{Limbs: [4]uint64{uint64(i), 0, 0, 0}}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = acc.Hash(input, HashConfig{Algorithm: "poseidon", Rate: 8})
	}
}

func BenchmarkGoAccelerator_BatchHash_10x8(b *testing.B) {
	config := DefaultConfig()
	acc, _ := NewGoAccelerator(config)
	defer acc.Close()

	inputs := make([][]FieldElement, 10)
	for i := range inputs {
		inputs[i] = make([]FieldElement, 8)
		for j := range inputs[i] {
			inputs[i][j] = FieldElement{Limbs: [4]uint64{uint64(i*8 + j), 0, 0, 0}}
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = acc.BatchHash(inputs, HashConfig{Algorithm: "poseidon"})
	}
}

func BenchmarkGoAccelerator_BatchHash_100x8(b *testing.B) {
	config := DefaultConfig()
	acc, _ := NewGoAccelerator(config)
	defer acc.Close()

	inputs := make([][]FieldElement, 100)
	for i := range inputs {
		inputs[i] = make([]FieldElement, 8)
		for j := range inputs[i] {
			inputs[i][j] = FieldElement{Limbs: [4]uint64{uint64(i*8 + j), 0, 0, 0}}
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = acc.BatchHash(inputs, HashConfig{Algorithm: "poseidon"})
	}
}

func BenchmarkGoAccelerator_GenerateProof(b *testing.B) {
	config := DefaultConfig()
	acc, _ := NewGoAccelerator(config)
	defer acc.Close()

	witness := make([]FieldElement, 256)
	publicInput := make([]FieldElement, 8)
	pk := &ProvingKey{System: "groth16"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = acc.GenerateProof(witness, publicInput, pk)
	}
}

func BenchmarkGoAccelerator_VerifyProof(b *testing.B) {
	config := DefaultConfig()
	acc, _ := NewGoAccelerator(config)
	defer acc.Close()

	witness := make([]FieldElement, 256)
	publicInput := make([]FieldElement, 8)
	pk := &ProvingKey{System: "groth16"}
	vk := &VerifyingKey{System: "groth16"}

	proof, _ := acc.GenerateProof(witness, publicInput, pk)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = acc.VerifyProof(proof, publicInput, vk)
	}
}

func BenchmarkGoAccelerator_FHEAdd(b *testing.B) {
	config := DefaultConfig()
	config.EnableFHE = true
	acc, _ := NewGoAccelerator(config)
	defer acc.Close()

	ct := &Ciphertext{
		Data:       make([]byte, 1024),
		Scheme:     "TFHE",
		NoiseLevel: 1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = acc.FHEAdd(ct, ct)
	}
}

func BenchmarkGoAccelerator_FHEMul(b *testing.B) {
	config := DefaultConfig()
	config.EnableFHE = true
	acc, _ := NewGoAccelerator(config)
	defer acc.Close()

	ct := &Ciphertext{
		Data:       make([]byte, 1024),
		Scheme:     "TFHE",
		NoiseLevel: 1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = acc.FHEMul(ct, ct)
	}
}

func BenchmarkGoAccelerator_FHEBootstrap(b *testing.B) {
	config := DefaultConfig()
	config.EnableFHE = true
	acc, _ := NewGoAccelerator(config)
	defer acc.Close()

	ct := &Ciphertext{
		Data:       make([]byte, 1024),
		Scheme:     "TFHE",
		NoiseLevel: 10,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = acc.FHEBootstrap(ct)
	}
}
