// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/log"
)

const (
	chainVMTestKey                                 = "chainVMTest"
	stateSyncEnabledTestKey                        = "stateSyncEnabledTest"
	getOngoingSyncStateSummaryTestKey              = "getOngoingSyncStateSummaryTest"
	getLastStateSummaryTestKey                     = "getLastStateSummaryTest"
	parseStateSummaryTestKey                       = "parseStateSummaryTest"
	getStateSummaryTestKey                         = "getStateSummaryTest"
	acceptStateSummaryTestKey                      = "acceptStateSummaryTest"
	lastAcceptedBlockPostStateSummaryAcceptTestKey = "lastAcceptedBlockPostStateSummaryAcceptTest"
	contextTestKey                                 = "contextTest"
	batchedParseBlockCachingTestKey                = "batchedParseBlockCachingTest"
)

var TestServerPluginMap = map[string]func(*testing.T, bool) block.ChainVM{
	stateSyncEnabledTestKey:                        stateSyncEnabledTestPlugin,
	getOngoingSyncStateSummaryTestKey:              getOngoingSyncStateSummaryTestPlugin,
	getLastStateSummaryTestKey:                     getLastStateSummaryTestPlugin,
	parseStateSummaryTestKey:                       parseStateSummaryTestPlugin,
	getStateSummaryTestKey:                         getStateSummaryTestPlugin,
	acceptStateSummaryTestKey:                      acceptStateSummaryTestPlugin,
	lastAcceptedBlockPostStateSummaryAcceptTestKey: lastAcceptedBlockPostStateSummaryAcceptTestPlugin,
	contextTestKey:                                 contextEnabledTestPlugin,
	batchedParseBlockCachingTestKey:                batchedParseBlockCachingTestPlugin,
}

// helperProcess helps with creating the net binary for testing.
func helperProcess(s ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--"}
	cs = append(cs, s...)
	env := []string{
		"TEST_PROCESS=1",
	}
	run := os.Args[0]
	cmd := exec.Command(run, cs...)
	env = append(env, os.Environ()...)
	cmd.Env = env
	return cmd
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("TEST_PROCESS") != "1" {
		return
	}

	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "failed to receive testKey")
		os.Exit(2)
	}

	testKey := args[0]
	if testKey == "dummy" {
		// block till killed
		select {}
	}

	pluginFunc, ok := TestServerPluginMap[testKey]
	if !ok {
		fmt.Fprintf(os.Stderr, "test plugin not found for key: %s\n", testKey)
		os.Exit(2)
	}
	mockedVM := pluginFunc(t, true /*loadExpectations*/)
	if mockedVM == nil {
		fmt.Fprintf(os.Stderr, "test plugin returned nil for key: %s\n", testKey)
		os.Exit(2)
	}
	err := Serve(context.Background(), log.NewTestLogger(log.DebugLevel), mockedVM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Serve failed: %v\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}
