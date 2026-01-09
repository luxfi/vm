// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quasar

import (
	"errors"
	"fmt"
	"time"
)

// Configuration errors
var (
	ErrInvalidK         = errors.New("K must be positive")
	ErrInvalidAlpha     = errors.New("alpha must be in (0, 1]")
	ErrInvalidBeta      = errors.New("beta must be positive and <= K")
	ErrInvalidThreshold = errors.New("threshold must be >= 2 and <= parties")
	ErrInvalidQuorum    = errors.New("quorum numerator must be <= denominator")
	ErrInvalidTimeout   = errors.New("timeout must be positive")
	ErrInvalidInterval  = errors.New("polling interval must be positive")
)

// -----------------------------------------------------------------------------
// Core Consensus Parameters (compile-time, immutable after construction)
// -----------------------------------------------------------------------------

// CoreParams defines the fundamental Snow consensus parameters.
// These are protocol-critical and must match across all validators.
type CoreParams struct {
	// K is the sample size for each consensus query round.
	// Typical values: 20-25 for production networks.
	K int

	// Alpha is the quorum threshold as a fraction of K.
	// A response is accepted if >= ceil(K * Alpha) validators agree.
	// Must be in (0.5, 1] for Byzantine fault tolerance.
	// Typical value: 0.8 (80% of sample must agree).
	Alpha float64

	// BetaVirtuous is the number of consecutive successful polls
	// required to finalize a virtuous (non-conflicting) decision.
	// Higher values increase latency but improve consistency.
	// Typical value: 15-20.
	BetaVirtuous int

	// BetaRogue is the number of consecutive successful polls
	// required to finalize a rogue (conflicting) decision.
	// Should be >= BetaVirtuous.
	// Typical value: 20-25.
	BetaRogue int
}

// Validate checks CoreParams invariants.
func (p CoreParams) Validate() error {
	if p.K <= 0 {
		return ErrInvalidK
	}
	if p.Alpha <= 0 || p.Alpha > 1 {
		return ErrInvalidAlpha
	}
	if p.BetaVirtuous <= 0 || p.BetaVirtuous > p.K {
		return ErrInvalidBeta
	}
	if p.BetaRogue <= 0 || p.BetaRogue > p.K {
		return ErrInvalidBeta
	}
	if p.BetaRogue < p.BetaVirtuous {
		return fmt.Errorf("BetaRogue (%d) must be >= BetaVirtuous (%d)", p.BetaRogue, p.BetaVirtuous)
	}
	return nil
}

// AlphaThreshold returns the minimum agreements needed for quorum.
func (p CoreParams) AlphaThreshold() int {
	return int(float64(p.K)*p.Alpha + 0.999) // ceil
}

// DefaultCoreParams returns production-ready core parameters.
func DefaultCoreParams() CoreParams {
	return CoreParams{
		K:            20,
		Alpha:        0.8,
		BetaVirtuous: 15,
		BetaRogue:    20,
	}
}

// -----------------------------------------------------------------------------
// Threshold Signing Parameters (compile-time, for Ringtail/BLS threshold)
// -----------------------------------------------------------------------------

// ThresholdParams defines t-of-n threshold signature configuration.
type ThresholdParams struct {
	// NumParties is the total number of signing parties (validators).
	// Must be >= 3 for threshold signatures.
	NumParties int

	// Threshold is the minimum signers required (t in t-of-n).
	// For BFT: typically 2/3 + 1.
	// Must be >= 2 and <= NumParties.
	Threshold int
}

// Validate checks ThresholdParams invariants.
func (p ThresholdParams) Validate() error {
	if p.NumParties < 3 {
		return fmt.Errorf("%w: need at least 3 parties, got %d", ErrInvalidThreshold, p.NumParties)
	}
	if p.Threshold < 2 || p.Threshold > p.NumParties {
		return fmt.Errorf("%w: threshold=%d, parties=%d", ErrInvalidThreshold, p.Threshold, p.NumParties)
	}
	return nil
}

// DefaultThresholdParams returns 2/3+1 threshold for n parties.
func DefaultThresholdParams(numParties int) ThresholdParams {
	threshold := (numParties * 2 / 3) + 1
	if threshold < 2 {
		threshold = 2
	}
	if threshold > numParties {
		threshold = numParties
	}
	return ThresholdParams{
		NumParties: numParties,
		Threshold:  threshold,
	}
}

// -----------------------------------------------------------------------------
// Quorum Parameters (compile-time, for BLS aggregate weight verification)
// -----------------------------------------------------------------------------

// QuorumParams defines weight-based quorum requirements.
type QuorumParams struct {
	// Numerator and Denominator define the minimum weight fraction.
	// Quorum is met when SignerWeight/TotalWeight >= Numerator/Denominator.
	// For BFT: typically 2/3 (Numerator=2, Denominator=3).
	Numerator   uint64
	Denominator uint64
}

// Validate checks QuorumParams invariants.
func (p QuorumParams) Validate() error {
	if p.Denominator == 0 {
		return fmt.Errorf("%w: denominator cannot be zero", ErrInvalidQuorum)
	}
	if p.Numerator > p.Denominator {
		return fmt.Errorf("%w: numerator=%d > denominator=%d", ErrInvalidQuorum, p.Numerator, p.Denominator)
	}
	return nil
}

// RequiredWeight returns minimum weight needed for quorum given totalWeight.
func (p QuorumParams) RequiredWeight(totalWeight uint64) uint64 {
	return totalWeight * p.Numerator / p.Denominator
}

// IsMet returns true if signerWeight meets quorum given totalWeight.
func (p QuorumParams) IsMet(signerWeight, totalWeight uint64) bool {
	return signerWeight >= p.RequiredWeight(totalWeight)
}

// DefaultQuorumParams returns 2/3 quorum (67% of weight required).
func DefaultQuorumParams() QuorumParams {
	return QuorumParams{
		Numerator:   2,
		Denominator: 3,
	}
}

// -----------------------------------------------------------------------------
// Runtime Configuration (can be adjusted, but affects liveness not safety)
// -----------------------------------------------------------------------------

// RuntimeConfig holds tunable runtime parameters.
// These affect performance and liveness but not consensus safety.
type RuntimeConfig struct {
	// PollInterval is the delay between consensus query rounds.
	// Lower values decrease latency but increase network load.
	// Typical value: 100-500ms.
	PollInterval time.Duration

	// QueryTimeout is the maximum time to wait for query responses.
	// Must be > PollInterval.
	// Typical value: 2-5s.
	QueryTimeout time.Duration

	// FinalityChannelSize is the buffer size for the finality event channel.
	FinalityChannelSize int

	// MaxConcurrentQueries limits parallel outstanding queries.
	// 0 means unlimited.
	MaxConcurrentQueries int
}

// Validate checks RuntimeConfig invariants.
func (c RuntimeConfig) Validate() error {
	if c.PollInterval <= 0 {
		return ErrInvalidInterval
	}
	if c.QueryTimeout <= 0 {
		return ErrInvalidTimeout
	}
	if c.QueryTimeout < c.PollInterval {
		return fmt.Errorf("query timeout (%v) must be >= poll interval (%v)", c.QueryTimeout, c.PollInterval)
	}
	if c.FinalityChannelSize < 0 {
		return fmt.Errorf("finality channel size must be >= 0")
	}
	return nil
}

// DefaultRuntimeConfig returns production-ready runtime configuration.
func DefaultRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		PollInterval:         250 * time.Millisecond,
		QueryTimeout:         2 * time.Second,
		FinalityChannelSize:  100,
		MaxConcurrentQueries: 0, // unlimited
	}
}

// -----------------------------------------------------------------------------
// Complete Configuration
// -----------------------------------------------------------------------------

// Config is the complete Quasar consensus configuration.
// Use ConfigBuilder for fluent construction.
type Config struct {
	Core      CoreParams
	Threshold ThresholdParams
	Quorum    QuorumParams
	Runtime   RuntimeConfig
}

// Validate checks all configuration invariants.
func (c Config) Validate() error {
	if err := c.Core.Validate(); err != nil {
		return fmt.Errorf("core params: %w", err)
	}
	if err := c.Threshold.Validate(); err != nil {
		return fmt.Errorf("threshold params: %w", err)
	}
	if err := c.Quorum.Validate(); err != nil {
		return fmt.Errorf("quorum params: %w", err)
	}
	if err := c.Runtime.Validate(); err != nil {
		return fmt.Errorf("runtime config: %w", err)
	}
	return nil
}

// DefaultConfig returns a production-ready configuration.
// Call DefaultConfig().WithNumParties(n) to set validator count.
func DefaultConfig() Config {
	return Config{
		Core:      DefaultCoreParams(),
		Threshold: DefaultThresholdParams(5), // default 5 validators
		Quorum:    DefaultQuorumParams(),
		Runtime:   DefaultRuntimeConfig(),
	}
}

// -----------------------------------------------------------------------------
// ConfigBuilder provides fluent configuration construction
// -----------------------------------------------------------------------------

// ConfigBuilder enables fluent Config construction with validation.
type ConfigBuilder struct {
	config Config
	errs   []error
}

// NewConfigBuilder creates a builder starting from defaults.
func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{
		config: DefaultConfig(),
	}
}

// WithK sets the sample size.
func (b *ConfigBuilder) WithK(k int) *ConfigBuilder {
	b.config.Core.K = k
	return b
}

// WithAlpha sets the quorum fraction.
func (b *ConfigBuilder) WithAlpha(alpha float64) *ConfigBuilder {
	b.config.Core.Alpha = alpha
	return b
}

// WithBeta sets both BetaVirtuous and BetaRogue.
func (b *ConfigBuilder) WithBeta(virtuous, rogue int) *ConfigBuilder {
	b.config.Core.BetaVirtuous = virtuous
	b.config.Core.BetaRogue = rogue
	return b
}

// WithNumParties sets the validator count and computes 2/3+1 threshold.
func (b *ConfigBuilder) WithNumParties(n int) *ConfigBuilder {
	b.config.Threshold = DefaultThresholdParams(n)
	return b
}

// WithThreshold sets an explicit threshold (overrides default 2/3+1).
func (b *ConfigBuilder) WithThreshold(threshold int) *ConfigBuilder {
	b.config.Threshold.Threshold = threshold
	return b
}

// WithQuorum sets the quorum fraction as numerator/denominator.
func (b *ConfigBuilder) WithQuorum(num, denom uint64) *ConfigBuilder {
	b.config.Quorum.Numerator = num
	b.config.Quorum.Denominator = denom
	return b
}

// WithPollInterval sets the polling interval.
func (b *ConfigBuilder) WithPollInterval(d time.Duration) *ConfigBuilder {
	b.config.Runtime.PollInterval = d
	return b
}

// WithQueryTimeout sets the query timeout.
func (b *ConfigBuilder) WithQueryTimeout(d time.Duration) *ConfigBuilder {
	b.config.Runtime.QueryTimeout = d
	return b
}

// WithFinalityChannelSize sets the finality channel buffer size.
func (b *ConfigBuilder) WithFinalityChannelSize(size int) *ConfigBuilder {
	b.config.Runtime.FinalityChannelSize = size
	return b
}

// Build validates and returns the configuration.
func (b *ConfigBuilder) Build() (Config, error) {
	if err := b.config.Validate(); err != nil {
		return Config{}, err
	}
	return b.config, nil
}

// MustBuild validates and returns the configuration, panicking on error.
// Use only in tests or when configuration is known to be valid.
func (b *ConfigBuilder) MustBuild() Config {
	cfg, err := b.Build()
	if err != nil {
		panic(fmt.Sprintf("invalid config: %v", err))
	}
	return cfg
}
