//go:build !grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"context"
	"fmt"
	"net"
	"os"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/log"
	"github.com/luxfi/metric"
	"github.com/luxfi/resource"
	"github.com/luxfi/vm/manager"
	"github.com/luxfi/vm/rpc/runtime"
	"github.com/luxfi/vm/rpc/runtime/subprocess"
)

var _ manager.Factory = (*factory)(nil)

type factory struct {
	path            string
	processTracker  resource.ProcessTracker
	runtimeTracker  runtime.Tracker
	metricsGatherer metric.MultiGatherer
}

// NewFactory creates a new VM factory for external plugin VMs using ZAP transport.
func NewFactory(
	path string,
	processTracker resource.ProcessTracker,
	runtimeTracker runtime.Tracker,
	metricsGatherer metric.MultiGatherer,
) manager.Factory {
	return &factory{
		path:            path,
		processTracker:  processTracker,
		runtimeTracker:  runtimeTracker,
		metricsGatherer: metricsGatherer,
	}
}

func (f *factory) New(logger log.Logger) (interface{}, error) {
	config := &subprocess.Config{
		Stderr:           os.Stderr,
		Stdout:           os.Stdout,
		HandshakeTimeout: runtime.DefaultHandshakeTimeout,
		Log:              logger,
	}

	// Create TCP listener for ZAP handshake
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to create ZAP listener: %w", err)
	}

	// Tell subprocess to use ZAP transport
	cmd := subprocess.NewCmd(f.path)
	cmd.Env = append(cmd.Env, "LUX_VM_TRANSPORT=zap")

	status, stopper, err := subprocess.Bootstrap(
		context.TODO(),
		listener,
		cmd,
		config,
	)
	if err != nil {
		return nil, err
	}

	// Connect via ZAP
	ctx, cancel := context.WithTimeout(context.Background(), runtime.DefaultHandshakeTimeout)
	defer cancel()

	zapConn, err := zapwire.Dial(ctx, status.Addr, nil)
	if err != nil {
		stopper.Stop(context.Background())
		logger.Error("failed to dial VM ZAP service", "error", err)
		return nil, err
	}

	f.processTracker.TrackProcess(status.Pid)
	f.runtimeTracker.TrackRuntime(stopper)

	logger.Info("VM client connected via ZAP",
		"path", f.path,
		"addr", status.Addr,
		"pid", status.Pid,
	)

	return NewZAPClient(zapConn, stopper, status.Pid, f.processTracker, f.metricsGatherer, logger), nil
}
