// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metrics

// Enabled tracks whether metrics collection is enabled
var Enabled bool

// Common metric interfaces
type (
	// Counter is a monotonically increasing counter
	Counter interface {
		Inc(int64)
		Dec(int64)
		Clear()
		Count() int64
		Snapshot() Counter
	}

	// CounterFloat64 is a float64 counter
	CounterFloat64 interface {
		Inc(float64)
		Dec(float64)
		Clear()
		Count() float64
		Snapshot() CounterFloat64
	}

	// Gauge holds an int64 value
	Gauge interface {
		Update(int64)
		Value() int64
		Snapshot() Gauge
	}

	// GaugeFloat64 holds a float64 value
	GaugeFloat64 interface {
		Update(float64)
		Value() float64
		Snapshot() GaugeFloat64
	}

	// GaugeInfo holds string information
	GaugeInfo interface {
		Update(GaugeInfoValue)
		Value() GaugeInfoValue
		Snapshot() GaugeInfo
	}

	// Histogram tracks the distribution of values
	Histogram interface {
		Update(int64)
		Count() int64
		Max() int64
		Mean() float64
		Min() int64
		Percentile(float64) float64
		Percentiles([]float64) []float64
		StdDev() float64
		Sum() int64
		Variance() float64
		Snapshot() Histogram
		Clear()
	}

	// Meter measures the rate of events
	Meter interface {
		Mark(int64)
		Count() int64
		Rate1() float64
		Rate5() float64
		Rate15() float64
		RateMean() float64
		Snapshot() Meter
		Stop()
	}

	// Timer measures durations
	Timer interface {
		Time(func())
		Update(int64)
		UpdateSince(int64)
		Count() int64
		Max() int64
		Mean() float64
		Min() int64
		Percentile(float64) float64
		Percentiles([]float64) []float64
		Rate1() float64
		Rate5() float64
		Rate15() float64
		RateMean() float64
		StdDev() float64
		Sum() int64
		Variance() float64
		Snapshot() Timer
		Stop()
	}

	// Sample represents a sample
	Sample interface {
		Clear()
		Count() int64
		Max() int64
		Mean() float64
		Min() int64
		Percentile(float64) float64
		Percentiles([]float64) []float64
		Size() int
		Snapshot() Sample
		StdDev() float64
		Sum() int64
		Update(int64)
		Values() []int64
		Variance() float64
	}

	// ResettingTimer is a timer that resets
	ResettingTimer interface {
		Time(func())
		Update(int64)
		UpdateSince(int64)
		Values() []int64
		Snapshot() ResettingTimer
		Percentiles([]float64) []float64
		Count() int64
		Mean() float64
	}

	// EWMA is an exponentially weighted moving average
	EWMA interface {
		Rate() float64
		Update(int64)
		Tick()
		Snapshot() EWMA
	}

	// Healthcheck tracks health status
	Healthcheck interface {
		Check()
		Error() error
		Healthy()
		Unhealthy(error)
	}
)

// GaugeInfoValue represents gauge info
type GaugeInfoValue map[string]string

// Nil implementations for when metrics are disabled
type (
	NilCounter        struct{}
	NilCounterFloat64 struct{}
	NilGauge          struct{}
	NilGaugeFloat64   struct{}
	NilGaugeInfo      struct{}
	NilHistogram      struct{}
	NilMeter          struct{}
	NilTimer          struct{}
	NilSample         struct{}
	NilResettingTimer struct{}
	NilEWMA           struct{}
	NilHealthcheck    struct{}
)

// NilCounter implementation
func (NilCounter) Inc(int64)           {}
func (NilCounter) Dec(int64)           {}
func (NilCounter) Clear()              {}
func (NilCounter) Count() int64        { return 0 }
func (n NilCounter) Snapshot() Counter { return n }

// NilCounterFloat64 implementation
func (NilCounterFloat64) Inc(float64)                {}
func (NilCounterFloat64) Dec(float64)                {}
func (NilCounterFloat64) Clear()                     {}
func (NilCounterFloat64) Count() float64             { return 0 }
func (n NilCounterFloat64) Snapshot() CounterFloat64 { return n }

// NilGauge implementation
func (NilGauge) Update(int64)      {}
func (NilGauge) Value() int64      { return 0 }
func (n NilGauge) Snapshot() Gauge { return n }

// NilGaugeFloat64 implementation
func (NilGaugeFloat64) Update(float64)           {}
func (NilGaugeFloat64) Value() float64           { return 0 }
func (n NilGaugeFloat64) Snapshot() GaugeFloat64 { return n }

// NilGaugeInfo implementation
func (NilGaugeInfo) Update(GaugeInfoValue) {}
func (NilGaugeInfo) Value() GaugeInfoValue { return nil }
func (n NilGaugeInfo) Snapshot() GaugeInfo { return n }

// NilHistogram implementation
func (NilHistogram) Update(int64)                    {}
func (NilHistogram) Count() int64                    { return 0 }
func (NilHistogram) Max() int64                      { return 0 }
func (NilHistogram) Mean() float64                   { return 0 }
func (NilHistogram) Min() int64                      { return 0 }
func (NilHistogram) Percentile(float64) float64      { return 0 }
func (NilHistogram) Percentiles([]float64) []float64 { return nil }
func (NilHistogram) StdDev() float64                 { return 0 }
func (NilHistogram) Sum() int64                      { return 0 }
func (NilHistogram) Variance() float64               { return 0 }
func (n NilHistogram) Snapshot() Histogram           { return n }
func (NilHistogram) Clear()                          {}

// NilMeter implementation
func (NilMeter) Mark(int64)        {}
func (NilMeter) Count() int64      { return 0 }
func (NilMeter) Rate1() float64    { return 0 }
func (NilMeter) Rate5() float64    { return 0 }
func (NilMeter) Rate15() float64   { return 0 }
func (NilMeter) RateMean() float64 { return 0 }
func (n NilMeter) Snapshot() Meter { return n }
func (NilMeter) Stop()             {}

// NilTimer implementation
func (NilTimer) Time(func())                     {}
func (NilTimer) Update(int64)                    {}
func (NilTimer) UpdateSince(int64)               {}
func (NilTimer) Count() int64                    { return 0 }
func (NilTimer) Max() int64                      { return 0 }
func (NilTimer) Mean() float64                   { return 0 }
func (NilTimer) Min() int64                      { return 0 }
func (NilTimer) Percentile(float64) float64      { return 0 }
func (NilTimer) Percentiles([]float64) []float64 { return nil }
func (NilTimer) Rate1() float64                  { return 0 }
func (NilTimer) Rate5() float64                  { return 0 }
func (NilTimer) Rate15() float64                 { return 0 }
func (NilTimer) RateMean() float64               { return 0 }
func (NilTimer) StdDev() float64                 { return 0 }
func (NilTimer) Sum() int64                      { return 0 }
func (NilTimer) Variance() float64               { return 0 }
func (n NilTimer) Snapshot() Timer               { return n }
func (NilTimer) Stop()                           {}

// NilSample implementation
func (NilSample) Clear()                          {}
func (NilSample) Count() int64                    { return 0 }
func (NilSample) Max() int64                      { return 0 }
func (NilSample) Mean() float64                   { return 0 }
func (NilSample) Min() int64                      { return 0 }
func (NilSample) Percentile(float64) float64      { return 0 }
func (NilSample) Percentiles([]float64) []float64 { return nil }
func (NilSample) Size() int                       { return 0 }
func (n NilSample) Snapshot() Sample              { return n }
func (NilSample) StdDev() float64                 { return 0 }
func (NilSample) Sum() int64                      { return 0 }
func (NilSample) Update(int64)                    {}
func (NilSample) Values() []int64                 { return nil }
func (NilSample) Variance() float64               { return 0 }

// NilResettingTimer implementation
func (NilResettingTimer) Time(func())                     {}
func (NilResettingTimer) Update(int64)                    {}
func (NilResettingTimer) UpdateSince(int64)               {}
func (NilResettingTimer) Values() []int64                 { return nil }
func (n NilResettingTimer) Snapshot() ResettingTimer      { return n }
func (NilResettingTimer) Percentiles([]float64) []float64 { return nil }
func (NilResettingTimer) Count() int64                    { return 0 }
func (NilResettingTimer) Mean() float64                   { return 0 }

// NilEWMA implementation
func (NilEWMA) Rate() float64    { return 0 }
func (NilEWMA) Update(int64)     {}
func (NilEWMA) Tick()            {}
func (n NilEWMA) Snapshot() EWMA { return n }

// NilHealthcheck implementation
func (NilHealthcheck) Check()          {}
func (NilHealthcheck) Error() error    { return nil }
func (NilHealthcheck) Healthy()        {}
func (NilHealthcheck) Unhealthy(error) {}
