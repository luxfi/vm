// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpcchainvm

import (
	"context"
	"fmt"
	"os"

	"github.com/luxfi/log"
	"github.com/luxfi/metric"
	"github.com/luxfi/vm/rpcchainvm/grpcutils"
	"github.com/luxfi/vm/utils/resource"
	"github.com/luxfi/vm/vms"
	"github.com/luxfi/vm/vms/rpcchainvm/runtime"
	"github.com/luxfi/vm/vms/rpcchainvm/runtime/subprocess"
)

var _ vms.Factory = (*factory)(nil)

type factory struct {
	path            string
	processTracker  resource.ProcessTracker
	runtimeTracker  runtime.Tracker
	metricsGatherer metric.MultiGatherer
}

func NewFactory(
	path string,
	processTracker resource.ProcessTracker,
	runtimeTracker runtime.Tracker,
	metricsGatherer metric.MultiGatherer,
) vms.Factory {
	return &factory{
		path:            path,
		processTracker:  processTracker,
		runtimeTracker:  runtimeTracker,
		metricsGatherer: metricsGatherer,
	}
}

func (f *factory) New(log log.Logger) (interface{}, error) {
	config := &subprocess.Config{
		Stderr:           os.Stderr, // capture VM subprocess stderr for debugging
		Stdout:           os.Stdout, // capture VM subprocess stdout for debugging
		HandshakeTimeout: runtime.DefaultHandshakeTimeout,
		Log:              log,
	}

	listener, err := grpcutils.NewListener()
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	status, stopper, err := subprocess.Bootstrap(
		context.TODO(),
		listener,
		subprocess.NewCmd(f.path),
		config,
	)
	if err != nil {
		return nil, err
	}

	clientConn, err := grpcutils.Dial(status.Addr)
	if err != nil {
		log.Error("failed to dial VM gRPC service", "error", err)
		return nil, err
	}

	f.processTracker.TrackProcess(status.Pid)
	f.runtimeTracker.TrackRuntime(stopper)
	return NewClient(clientConn, stopper, status.Pid, f.processTracker, f.metricsGatherer, log), nil
}
