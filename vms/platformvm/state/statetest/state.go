// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package statetest

import (
	"testing"
	"time"

	"github.com/luxfi/metric"
	"github.com/stretchr/testify/require"

	consensusctx "github.com/luxfi/consensus/context"
	validators "github.com/luxfi/consensus/validator"
	"github.com/luxfi/constants"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/upgrade"
	"github.com/luxfi/upgrade/upgradetest"
	"github.com/luxfi/vm/vms/platformvm/config"
	"github.com/luxfi/vm/vms/platformvm/genesis/genesistest"
	"github.com/luxfi/vm/vms/platformvm/metrics"
	"github.com/luxfi/vm/vms/platformvm/reward"
	"github.com/luxfi/vm/vms/platformvm/state"
)

var DefaultNodeID = ids.GenerateTestNodeID()

type Config struct {
	DB         database.Database
	Genesis    []byte
	Registerer metric.Registerer
	Validators validators.Manager
	Upgrades   upgrade.Config
	Config     config.Config
	Context    *consensusctx.Context
	Metrics    metrics.Metrics
	Rewards    reward.Calculator
}

func New(t testing.TB, c Config) state.State {
	if c.DB == nil {
		c.DB = memdb.New()
	}
	if c.Context == nil {
		c.Context = &consensusctx.Context{
			NetworkID: constants.UnitTestID,
			NodeID:    DefaultNodeID,
			Log:       log.NoLog{},
		}
	}
	if len(c.Genesis) == 0 {
		c.Genesis = genesistest.NewBytes(t, genesistest.Config{
			NetworkID: c.Context.NetworkID,
		})
	}
	if c.Registerer == nil {
		c.Registerer = metric.NewRegistry()
	}
	if c.Validators == nil {
		c.Validators = validators.NewManager()
	}
	if c.Upgrades == (upgrade.Config{}) {
		c.Upgrades = upgradetest.GetConfig(upgradetest.Latest)
	}
	if c.Config.BlockCacheSize == 0 {
		c.Config = config.Default
	}
	if c.Metrics == nil {
		c.Metrics = metrics.Noop
	}
	if c.Rewards == nil {
		c.Rewards = reward.NewCalculator(reward.Config{
			MaxConsumptionRate: .12 * reward.PercentDenominator,
			MinConsumptionRate: .1 * reward.PercentDenominator,
			MintingPeriod:      365 * 24 * time.Hour,
			SupplyCap:          720 * constants.MegaLux,
		})
	}

	s, err := state.New(
		c.DB,
		c.Genesis,
		c.Registerer,
		c.Validators,
		c.Upgrades,
		&c.Config,
		c.Context,
		c.Metrics,
		c.Rewards,
	)
	require.NoError(t, err)
	return s
}
