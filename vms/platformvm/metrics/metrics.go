// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metrics

import (
	"errors"
	"time"

	"github.com/luxfi/metric"

	"github.com/luxfi/ids"
	utilmetric "github.com/luxfi/vm/utils/metric"
	"github.com/luxfi/vm/utils/wrappers"
	"github.com/luxfi/vm/vms/components/gas"
	"github.com/luxfi/vm/vms/platformvm/block"
)

const (
	ResourceLabel   = "resource"
	GasLabel        = "gas"
	ValidatorsLabel = "validators"
)

var (
	gasLabels = metric.Labels{
		ResourceLabel: GasLabel,
	}
	validatorsLabels = metric.Labels{
		ResourceLabel: ValidatorsLabel,
	}
)

var _ Metrics = (*metricsImpl)(nil)

type Block struct {
	Block block.Block

	GasConsumed gas.Gas
	GasState    gas.State
	GasPrice    gas.Price

	ActiveL1Validators   int
	ValidatorExcess      gas.Gas
	ValidatorPrice       gas.Price
	AccruedValidatorFees uint64
}

type Metrics interface {
	utilmetric.APIInterceptor

	// Mark that the given block was accepted.
	MarkAccepted(Block) error

	// Mark that a validator set was created.
	IncValidatorSetsCreated()
	// Mark that a validator set was cached.
	IncValidatorSetsCached()
	// Mark that we spent the given time computing validator diffs.
	AddValidatorSetsDuration(time.Duration)
	// Mark that we computed a validator diff at a height with the given
	// difference from the top.
	AddValidatorSetsHeightDiff(uint64)

	// Mark that this much stake is staked on the node.
	SetLocalStake(uint64)
	// Mark that this much stake is staked in the network.
	SetTotalStake(uint64)
	// Mark when this node will unstake from the Primary Network.
	SetTimeUntilUnstake(time.Duration)
	// Mark when this node will unstake from a net.
	SetTimeUntilNetUnstake(netID ids.ID, timeUntilUnstake time.Duration)
}

func New(registerer metric.Registerer) (Metrics, error) {
	blockMetrics, err := newBlockMetrics(registerer)
	m := &metricsImpl{
		blockMetrics: blockMetrics,
		timeUntilUnstake: metric.NewGauge(metric.GaugeOpts{
			Name: "time_until_unstake",
			Help: "Time (in ns) until this node leaves the Primary Network's validator set",
		}),
		timeUntilNetUnstake: metric.NewGaugeVec(
			metric.GaugeOpts{
				Name: "time_until_unstake_net",
				Help: "Time (in ns) until this node leaves the net's validator set",
			},
			[]string{"netID"},
		),
		localStake: metric.NewGauge(metric.GaugeOpts{
			Name: "local_staked",
			Help: "Amount (in nLUX) of LUX staked on this node",
		}),
		totalStake: metric.NewGauge(metric.GaugeOpts{
			Name: "total_staked",
			Help: "Amount (in nLUX) of LUX staked on the Primary Network",
		}),

		gasConsumed: metric.NewCounter(metric.CounterOpts{
			Name: "gas_consumed",
			Help: "Cumulative amount of gas consumed by transactions",
		}),
		gasCapacity: metric.NewGauge(metric.GaugeOpts{
			Name: "gas_capacity",
			Help: "Minimum amount of gas that can be consumed in the next block",
		}),
		activeL1Validators: metric.NewGauge(metric.GaugeOpts{
			Name: "active_l1_validators",
			Help: "Number of active L1 validators",
		}),
		excess: metric.NewGaugeVec(
			metric.GaugeOpts{
				Name: "excess",
				Help: "Excess usage of a resource over the target usage",
			},
			[]string{ResourceLabel},
		),
		price: metric.NewGaugeVec(
			metric.GaugeOpts{
				Name: "price",
				Help: "Price (in nLUX) of a resource",
			},
			[]string{ResourceLabel},
		),
		accruedValidatorFees: metric.NewGauge(metric.GaugeOpts{
			Name: "accrued_validator_fees",
			Help: "The total cost of running an active L1 validator since Etna activation",
		}),

		validatorSetsCached: metric.NewCounter(metric.CounterOpts{
			Name: "validator_sets_cached",
			Help: "Total number of validator sets cached",
		}),
		validatorSetsCreated: metric.NewCounter(metric.CounterOpts{
			Name: "validator_sets_created",
			Help: "Total number of validator sets created from applying difflayers",
		}),
		validatorSetsHeightDiff: metric.NewGauge(metric.GaugeOpts{
			Name: "validator_sets_height_diff_sum",
			Help: "Total number of validator sets diffs applied for generating validator sets",
		}),
		validatorSetsDuration: metric.NewGauge(metric.GaugeOpts{
			Name: "validator_sets_duration_sum",
			Help: "Total amount of time generating validator sets in nanoseconds",
		}),
	}

	errs := wrappers.Errs{Err: err}
	registry, ok := registerer.(metric.Registry)
	if !ok {
		return nil, errors.New("registerer must be a Registry")
	}
	apiRequestMetrics, err := utilmetric.NewAPIInterceptor(registry)
	errs.Add(err)
	m.APIInterceptor = apiRequestMetrics

	errs.Add(
		registerer.Register(metric.AsCollector(m.timeUntilUnstake)),
		registerer.Register(metric.AsCollector(m.timeUntilNetUnstake)),
		registerer.Register(metric.AsCollector(m.localStake)),
		registerer.Register(metric.AsCollector(m.totalStake)),
		registerer.Register(metric.AsCollector(m.gasConsumed)),
		registerer.Register(metric.AsCollector(m.gasCapacity)),
		registerer.Register(metric.AsCollector(m.activeL1Validators)),
		registerer.Register(metric.AsCollector(m.excess)),
		registerer.Register(metric.AsCollector(m.price)),
		registerer.Register(metric.AsCollector(m.accruedValidatorFees)),

		registerer.Register(metric.AsCollector(m.validatorSetsCreated)),
		registerer.Register(metric.AsCollector(m.validatorSetsCached)),
		registerer.Register(metric.AsCollector(m.validatorSetsHeightDiff)),
		registerer.Register(metric.AsCollector(m.validatorSetsDuration)),
	)

	return m, errs.Err
}

type metricsImpl struct {
	utilmetric.APIInterceptor

	blockMetrics *blockMetrics

	// Staking metrics
	timeUntilUnstake    metric.Gauge
	timeUntilNetUnstake metric.GaugeVec
	localStake          metric.Gauge
	totalStake          metric.Gauge

	gasConsumed          metric.Counter
	gasCapacity          metric.Gauge
	activeL1Validators   metric.Gauge
	excess               metric.GaugeVec
	price                metric.GaugeVec
	accruedValidatorFees metric.Gauge

	// Validator set diff metrics
	validatorSetsCached     metric.Counter
	validatorSetsCreated    metric.Counter
	validatorSetsHeightDiff metric.Gauge
	validatorSetsDuration   metric.Gauge
}

func (m *metricsImpl) MarkAccepted(b Block) error {
	m.gasConsumed.Add(float64(b.GasConsumed))
	m.gasCapacity.Set(float64(b.GasState.Capacity))
	m.excess.With(gasLabels).Set(float64(b.GasState.Excess))
	m.price.With(gasLabels).Set(float64(b.GasPrice))

	m.activeL1Validators.Set(float64(b.ActiveL1Validators))
	m.excess.With(validatorsLabels).Set(float64(b.ValidatorExcess))
	m.price.With(validatorsLabels).Set(float64(b.ValidatorPrice))
	m.accruedValidatorFees.Set(float64(b.AccruedValidatorFees))

	return b.Block.Visit(m.blockMetrics)
}

func (m *metricsImpl) IncValidatorSetsCreated() {
	m.validatorSetsCreated.Inc()
}

func (m *metricsImpl) IncValidatorSetsCached() {
	m.validatorSetsCached.Inc()
}

func (m *metricsImpl) AddValidatorSetsDuration(d time.Duration) {
	m.validatorSetsDuration.Add(float64(d))
}

func (m *metricsImpl) AddValidatorSetsHeightDiff(d uint64) {
	m.validatorSetsHeightDiff.Add(float64(d))
}

func (m *metricsImpl) SetLocalStake(s uint64) {
	m.localStake.Set(float64(s))
}

func (m *metricsImpl) SetTotalStake(s uint64) {
	m.totalStake.Set(float64(s))
}

func (m *metricsImpl) SetTimeUntilUnstake(timeUntilUnstake time.Duration) {
	m.timeUntilUnstake.Set(float64(timeUntilUnstake))
}

func (m *metricsImpl) SetTimeUntilNetUnstake(netID ids.ID, timeUntilUnstake time.Duration) {
	m.timeUntilNetUnstake.WithLabelValues(netID.String()).Set(float64(timeUntilUnstake))
}
