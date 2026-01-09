// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package create

import (
	"log"
	"time"

	"github.com/spf13/cobra"

	"github.com/luxfi/constants"
	"github.com/luxfi/sdk/wallet/primary"
	"github.com/luxfi/sdk/wallet/primary/common"
	"github.com/luxfi/vm/secp256k1fx"
	"github.com/luxfi/vm/vms/example/xsvm/genesis"
)

func Command() *cobra.Command {
	c := &cobra.Command{
		Use:   "create",
		Short: "Creates a new chain",
		RunE:  createFunc,
	}
	flags := c.Flags()
	AddFlags(flags)
	return c
}

func createFunc(c *cobra.Command, args []string) error {
	flags := c.Flags()
	config, err := ParseFlags(flags, args)
	if err != nil {
		return err
	}

	ctx := c.Context()
	kc := secp256k1fx.NewKeychain(config.PrivateKey)

	// MakePWallet fetches the available UTXOs owned by [kc] on the P-chain that
	// [uri] is hosting.
	walletSyncStartTime := time.Now()
	// Use KeychainAdapter for wallet compatibility
	kcAdapter := primary.NewKeychainAdapter(kc)
	wallet, err := primary.MakeWallet(
		ctx,
		&primary.WalletConfig{
			URI:         config.URI,
			LUXKeychain: kcAdapter,
			EthKeychain: kcAdapter,
		},
	)
	if err != nil {
		return err
	}
	log.Printf("synced wallet in %s\n", time.Since(walletSyncStartTime))

	genesisBytes, err := genesis.Codec.Marshal(genesis.CodecVersion, &genesis.Genesis{
		Timestamp: 0,
		Allocations: []genesis.Allocation{
			{
				Address: config.Address,
				Balance: config.Balance,
			},
		},
	})
	if err != nil {
		return err
	}

	createChainStartTime := time.Now()
	createChainTxID, err := wallet.P().IssueCreateChainTx(
		config.NetID,
		genesisBytes,
		constants.XSVMID,
		nil,
		config.Name,
		common.WithContext(ctx),
	)
	if err != nil {
		return err
	}
	log.Printf("created chain %s in %s\n", createChainTxID, time.Since(createChainStartTime))
	return nil
}
