// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package run

import (
	"github.com/spf13/cobra"

	"github.com/luxfi/vm/vms/example/xsvm"
	"github.com/luxfi/vm/vms/rpcchainvm"
)

func Command() *cobra.Command {
	return &cobra.Command{
		Use:   "xsvm",
		Short: "Runs an XSVM plugin",
		RunE:  runFunc,
	}
}

func runFunc(*cobra.Command, []string) error {
	// TODO: Update xsvm.VM to implement current consensus ChainVM interface
	// The consensus interface now expects interface{} parameters for Initialize
	_ = rpcchainvm.Serve
	_ = &xsvm.VM{}
	return nil
}
