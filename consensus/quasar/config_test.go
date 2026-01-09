// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quasar

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}

	// Verify defaults match documentation
	if cfg.Core.K != 20 {
		t.Errorf("expected K=20, got %d", cfg.Core.K)
	}
	if cfg.Core.Alpha != 0.8 {
		t.Errorf("expected Alpha=0.8, got %f", cfg.Core.Alpha)
	}
	if cfg.Core.BetaVirtuous != 15 {
		t.Errorf("expected BetaVirtuous=15, got %d", cfg.Core.BetaVirtuous)
	}
	if cfg.Core.BetaRogue != 20 {
		t.Errorf("expected BetaRogue=20, got %d", cfg.Core.BetaRogue)
	}
	if cfg.Quorum.Numerator != 2 || cfg.Quorum.Denominator != 3 {
		t.Errorf("expected 2/3 quorum, got %d/%d", cfg.Quorum.Numerator, cfg.Quorum.Denominator)
	}
}

func TestCoreParamsValidation(t *testing.T) {
	tests := []struct {
		name    string
		params  CoreParams
		wantErr bool
	}{
		{
			name:    "valid defaults",
			params:  DefaultCoreParams(),
			wantErr: false,
		},
		{
			name:    "zero K",
			params:  CoreParams{K: 0, Alpha: 0.8, BetaVirtuous: 15, BetaRogue: 20},
			wantErr: true,
		},
		{
			name:    "negative K",
			params:  CoreParams{K: -1, Alpha: 0.8, BetaVirtuous: 15, BetaRogue: 20},
			wantErr: true,
		},
		{
			name:    "alpha zero",
			params:  CoreParams{K: 20, Alpha: 0, BetaVirtuous: 15, BetaRogue: 20},
			wantErr: true,
		},
		{
			name:    "alpha greater than 1",
			params:  CoreParams{K: 20, Alpha: 1.5, BetaVirtuous: 15, BetaRogue: 20},
			wantErr: true,
		},
		{
			name:    "alpha exactly 1",
			params:  CoreParams{K: 20, Alpha: 1.0, BetaVirtuous: 15, BetaRogue: 20},
			wantErr: false,
		},
		{
			name:    "beta virtuous zero",
			params:  CoreParams{K: 20, Alpha: 0.8, BetaVirtuous: 0, BetaRogue: 20},
			wantErr: true,
		},
		{
			name:    "beta rogue less than virtuous",
			params:  CoreParams{K: 20, Alpha: 0.8, BetaVirtuous: 20, BetaRogue: 15},
			wantErr: true,
		},
		{
			name:    "beta exceeds K",
			params:  CoreParams{K: 10, Alpha: 0.8, BetaVirtuous: 15, BetaRogue: 20},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAlphaThreshold(t *testing.T) {
	tests := []struct {
		k     int
		alpha float64
		want  int
	}{
		{k: 20, alpha: 0.8, want: 16},  // 20 * 0.8 = 16
		{k: 20, alpha: 0.51, want: 11}, // ceil(10.2) = 11
		{k: 10, alpha: 0.67, want: 7},  // ceil(6.7) = 7
		{k: 5, alpha: 1.0, want: 5},    // 5 * 1.0 = 5
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			p := CoreParams{K: tt.k, Alpha: tt.alpha, BetaVirtuous: 1, BetaRogue: 1}
			got := p.AlphaThreshold()
			if got != tt.want {
				t.Errorf("AlphaThreshold(%d, %f) = %d, want %d", tt.k, tt.alpha, got, tt.want)
			}
		})
	}
}

func TestThresholdParamsValidation(t *testing.T) {
	tests := []struct {
		name    string
		params  ThresholdParams
		wantErr bool
	}{
		{
			name:    "valid 3 of 5",
			params:  ThresholdParams{NumParties: 5, Threshold: 3},
			wantErr: false,
		},
		{
			name:    "valid 4 of 5",
			params:  ThresholdParams{NumParties: 5, Threshold: 4},
			wantErr: false,
		},
		{
			name:    "valid 2 of 3 minimum",
			params:  ThresholdParams{NumParties: 3, Threshold: 2},
			wantErr: false,
		},
		{
			name:    "too few parties",
			params:  ThresholdParams{NumParties: 2, Threshold: 2},
			wantErr: true,
		},
		{
			name:    "threshold too low",
			params:  ThresholdParams{NumParties: 5, Threshold: 1},
			wantErr: true,
		},
		{
			name:    "threshold exceeds parties",
			params:  ThresholdParams{NumParties: 5, Threshold: 6},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultThresholdParams(t *testing.T) {
	tests := []struct {
		parties       int
		wantThreshold int
	}{
		{parties: 3, wantThreshold: 3},  // 2/3 of 3 = 2, +1 = 3
		{parties: 4, wantThreshold: 3},  // 2/3 of 4 = 2, +1 = 3
		{parties: 5, wantThreshold: 4},  // 2/3 of 5 = 3, +1 = 4
		{parties: 10, wantThreshold: 7}, // 2/3 of 10 = 6, +1 = 7
		{parties: 21, wantThreshold: 15}, // 2/3 of 21 = 14, +1 = 15
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			p := DefaultThresholdParams(tt.parties)
			if p.Threshold != tt.wantThreshold {
				t.Errorf("DefaultThresholdParams(%d).Threshold = %d, want %d",
					tt.parties, p.Threshold, tt.wantThreshold)
			}
			if err := p.Validate(); err != nil {
				t.Errorf("DefaultThresholdParams(%d) produced invalid params: %v", tt.parties, err)
			}
		})
	}
}

func TestQuorumParamsValidation(t *testing.T) {
	tests := []struct {
		name    string
		params  QuorumParams
		wantErr bool
	}{
		{
			name:    "valid 2/3",
			params:  QuorumParams{Numerator: 2, Denominator: 3},
			wantErr: false,
		},
		{
			name:    "valid 1/2",
			params:  QuorumParams{Numerator: 1, Denominator: 2},
			wantErr: false,
		},
		{
			name:    "valid 1/1 (unanimous)",
			params:  QuorumParams{Numerator: 1, Denominator: 1},
			wantErr: false,
		},
		{
			name:    "zero denominator",
			params:  QuorumParams{Numerator: 2, Denominator: 0},
			wantErr: true,
		},
		{
			name:    "numerator exceeds denominator",
			params:  QuorumParams{Numerator: 4, Denominator: 3},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestQuorumIsMet(t *testing.T) {
	q := QuorumParams{Numerator: 2, Denominator: 3} // 2/3 = 66.67%

	// Note: integer math: 100 * 2 / 3 = 66 (floor division)
	tests := []struct {
		signerWeight uint64
		totalWeight  uint64
		want         bool
	}{
		{signerWeight: 67, totalWeight: 100, want: true},  // 67 >= 66
		{signerWeight: 66, totalWeight: 100, want: true},  // 66 >= 66 (floor division)
		{signerWeight: 65, totalWeight: 100, want: false}, // 65 < 66
		{signerWeight: 100, totalWeight: 100, want: true}, // 100 >= 66
		{signerWeight: 0, totalWeight: 100, want: false},  // 0 < 66
		{signerWeight: 2, totalWeight: 3, want: true},     // 2 >= 2 (3*2/3=2)
		{signerWeight: 1, totalWeight: 3, want: false},    // 1 < 2
	}

	for _, tt := range tests {
		got := q.IsMet(tt.signerWeight, tt.totalWeight)
		if got != tt.want {
			t.Errorf("IsMet(%d, %d) = %v, want %v", tt.signerWeight, tt.totalWeight, got, tt.want)
		}
	}
}

func TestRuntimeConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  RuntimeConfig
		wantErr bool
	}{
		{
			name:    "valid defaults",
			config:  DefaultRuntimeConfig(),
			wantErr: false,
		},
		{
			name: "zero poll interval",
			config: RuntimeConfig{
				PollInterval: 0,
				QueryTimeout: time.Second,
			},
			wantErr: true,
		},
		{
			name: "negative poll interval",
			config: RuntimeConfig{
				PollInterval: -time.Millisecond,
				QueryTimeout: time.Second,
			},
			wantErr: true,
		},
		{
			name: "query timeout less than poll interval",
			config: RuntimeConfig{
				PollInterval: time.Second,
				QueryTimeout: 100 * time.Millisecond,
			},
			wantErr: true,
		},
		{
			name: "negative channel size",
			config: RuntimeConfig{
				PollInterval:        250 * time.Millisecond,
				QueryTimeout:        2 * time.Second,
				FinalityChannelSize: -1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigBuilder(t *testing.T) {
	// Test fluent API
	cfg, err := NewConfigBuilder().
		WithK(25).
		WithAlpha(0.75).
		WithBeta(18, 22).
		WithNumParties(10).
		WithQuorum(3, 4). // 75%
		WithPollInterval(500 * time.Millisecond).
		WithQueryTimeout(5 * time.Second).
		Build()

	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if cfg.Core.K != 25 {
		t.Errorf("K = %d, want 25", cfg.Core.K)
	}
	if cfg.Core.Alpha != 0.75 {
		t.Errorf("Alpha = %f, want 0.75", cfg.Core.Alpha)
	}
	if cfg.Core.BetaVirtuous != 18 {
		t.Errorf("BetaVirtuous = %d, want 18", cfg.Core.BetaVirtuous)
	}
	if cfg.Core.BetaRogue != 22 {
		t.Errorf("BetaRogue = %d, want 22", cfg.Core.BetaRogue)
	}
	if cfg.Threshold.NumParties != 10 {
		t.Errorf("NumParties = %d, want 10", cfg.Threshold.NumParties)
	}
	if cfg.Threshold.Threshold != 7 { // 2/3 of 10 + 1 = 7
		t.Errorf("Threshold = %d, want 7", cfg.Threshold.Threshold)
	}
	if cfg.Quorum.Numerator != 3 || cfg.Quorum.Denominator != 4 {
		t.Errorf("Quorum = %d/%d, want 3/4", cfg.Quorum.Numerator, cfg.Quorum.Denominator)
	}
	if cfg.Runtime.PollInterval != 500*time.Millisecond {
		t.Errorf("PollInterval = %v, want 500ms", cfg.Runtime.PollInterval)
	}
}

func TestConfigBuilderWithExplicitThreshold(t *testing.T) {
	cfg, err := NewConfigBuilder().
		WithNumParties(10).
		WithThreshold(5). // Override default 7
		Build()

	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if cfg.Threshold.Threshold != 5 {
		t.Errorf("Threshold = %d, want 5", cfg.Threshold.Threshold)
	}
}

func TestConfigBuilderValidationError(t *testing.T) {
	_, err := NewConfigBuilder().
		WithK(-1). // Invalid
		Build()

	if err == nil {
		t.Error("Build() should return error for invalid K")
	}
}

func TestConfigBuilderMustBuildPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustBuild() should panic on invalid config")
		}
	}()

	NewConfigBuilder().WithK(-1).MustBuild()
}

func TestConfigBuilderMustBuildSuccess(t *testing.T) {
	// Should not panic
	cfg := NewConfigBuilder().MustBuild()
	if err := cfg.Validate(); err != nil {
		t.Errorf("MustBuild() produced invalid config: %v", err)
	}
}

// TestConfigImmutability documents that Config values are immutable after creation.
func TestConfigImmutability(t *testing.T) {
	cfg := DefaultConfig()

	// These are value types, so modifications don't affect the original
	core := cfg.Core
	core.K = 999

	if cfg.Core.K == 999 {
		t.Error("Config.Core should be immutable (value copy)")
	}
}

// BenchmarkQuorumCheck benchmarks the quorum check operation.
func BenchmarkQuorumCheck(b *testing.B) {
	q := DefaultQuorumParams()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = q.IsMet(70, 100)
	}
}

// BenchmarkConfigValidation benchmarks config validation.
func BenchmarkConfigValidation(b *testing.B) {
	cfg := DefaultConfig()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cfg.Validate()
	}
}
