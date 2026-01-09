// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metrics

import (
	"github.com/luxfi/metric"

	"github.com/luxfi/vm/vms/platformvm/txs"
)

const txLabel = "tx"

var (
	_ txs.Visitor = (*txMetrics)(nil)

	txLabels = []string{txLabel}
)

type txMetrics struct {
	numTxs metric.CounterVec
}

func newTxMetrics(registerer metric.Registerer) (*txMetrics, error) {
	m := &txMetrics{
		numTxs: metric.NewCounterVec(
			metric.CounterOpts{
				Name: "txs_accepted",
				Help: "number of transactions accepted",
			},
			txLabels,
		),
	}
	return m, nil
}

func (m *txMetrics) AddValidatorTx(*txs.AddValidatorTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "add_validator",
	}).Inc()
	return nil
}

// Removed in regenesis
// func (m *txMetrics) AddChainValidatorTx(*txs.AddChainValidatorTx) error {
// 	m.numTxs.With(metric.Labels{
// 		txLabel: "add_chain_validator",
// 	}).Inc()
// 	return nil
// }

func (m *txMetrics) AddDelegatorTx(*txs.AddDelegatorTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "add_delegator",
	}).Inc()
	return nil
}

func (m *txMetrics) CreateChainTx(*txs.CreateChainTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "create_chain",
	}).Inc()
	return nil
}

// Removed in regenesis
// func (m *txMetrics) CreateNetTx(*txs.CreateNetTx) error {
// 	m.numTxs.With(metric.Labels{
// 		txLabel: "create_chain",
// 	}).Inc()
// 	return nil
// }

func (m *txMetrics) ImportTx(*txs.ImportTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "import",
	}).Inc()
	return nil
}

func (m *txMetrics) ExportTx(*txs.ExportTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "export",
	}).Inc()
	return nil
}

func (m *txMetrics) AdvanceTimeTx(*txs.AdvanceTimeTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "advance_time",
	}).Inc()
	return nil
}

func (m *txMetrics) RewardValidatorTx(*txs.RewardValidatorTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "reward_validator",
	}).Inc()
	return nil
}

// Removed in regenesis
// func (m *txMetrics) RemoveChainValidatorTx(*txs.RemoveChainValidatorTx) error {
// 	m.numTxs.With(metric.Labels{
// 		txLabel: "remove_chain_validator",
// 	}).Inc()
// 	return nil
// }

// Removed in regenesis
// func (m *txMetrics) TransformChainTx(*txs.TransformChainTx) error {
// 	m.numTxs.With(metric.Labels{
// 		txLabel: "transform_chain",
// 	}).Inc()
// 	return nil
// }

func (m *txMetrics) AddPermissionlessValidatorTx(*txs.AddPermissionlessValidatorTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "add_permissionless_validator",
	}).Inc()
	return nil
}

func (m *txMetrics) AddPermissionlessDelegatorTx(*txs.AddPermissionlessDelegatorTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "add_permissionless_delegator",
	}).Inc()
	return nil
}

// Removed in regenesis
// func (m *txMetrics) TransferChainOwnershipTx(*txs.TransferChainOwnershipTx) error {
// 	m.numTxs.With(metric.Labels{
// 		txLabel: "transfer_chain_ownership",
// 	}).Inc()
// 	return nil
// }

func (m *txMetrics) BaseTx(*txs.BaseTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "base",
	}).Inc()
	return nil
}

func (m *txMetrics) ConvertChainToL1Tx(*txs.ConvertChainToL1Tx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "convert_net_to_l1",
	}).Inc()
	return nil
}

func (m *txMetrics) RegisterL1ValidatorTx(*txs.RegisterL1ValidatorTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "register_l1_validator",
	}).Inc()
	return nil
}

func (m *txMetrics) SetL1ValidatorWeightTx(*txs.SetL1ValidatorWeightTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "set_l1_validator_weight",
	}).Inc()
	return nil
}

func (m *txMetrics) IncreaseL1ValidatorBalanceTx(*txs.IncreaseL1ValidatorBalanceTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "increase_l1_validator_balance",
	}).Inc()
	return nil
}

func (m *txMetrics) DisableL1ValidatorTx(*txs.DisableL1ValidatorTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "disable_l1_validator",
	}).Inc()
	return nil
}

func (m *txMetrics) AddChainValidatorTx(*txs.AddChainValidatorTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "add_net_validator",
	}).Inc()
	return nil
}

func (m *txMetrics) CreateChainTx(*txs.CreateChainTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "create_chain",
	}).Inc()
	return nil
}

func (m *txMetrics) RemoveChainValidatorTx(*txs.RemoveChainValidatorTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "remove_net_validator",
	}).Inc()
	return nil
}

func (m *txMetrics) TransformChainTx(*txs.TransformChainTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "transform_net",
	}).Inc()
	return nil
}

func (m *txMetrics) TransferChainOwnershipTx(*txs.TransferChainOwnershipTx) error {
	m.numTxs.With(metric.Labels{
		txLabel: "transfer_net_ownership",
	}).Inc()
	return nil
}
