// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package subprocess

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/luxfi/log"
	"github.com/luxfi/vm/vms/rpcchainvm/grpcutils"
	"github.com/luxfi/vm/vms/rpcchainvm/gruntime"
	"github.com/luxfi/vm/vms/rpcchainvm/runtime"

	pb "github.com/luxfi/vm/proto/pb/vm/runtime"
)

type Config struct {
	// Stderr of the VM process written to this writer.
	Stderr io.Writer
	// Stdout of the VM process written to this writer.
	Stdout io.Writer
	// Duration engine server will wait for handshake success.
	HandshakeTimeout time.Duration
	Log              log.Logger
}

type Status struct {
	// Id of the process.
	Pid int
	// Address of the VM gRPC service.
	Addr string
}

// Bootstrap starts a VM as a subprocess after initialization completes and
// pipes the IO to the appropriate writers.
//
// The subprocess is expected to be stopped by the caller if a non-nil error is
// returned. If piping the IO fails then the subprocess will be stopped.
func Bootstrap(
	ctx context.Context,
	listener net.Listener,
	cmd *exec.Cmd,
	config *Config,
) (*Status, runtime.Stopper, error) {
	defer listener.Close()

	switch {
	case cmd == nil:
		return nil, nil, fmt.Errorf("%w: cmd required", runtime.ErrInvalidConfig)
	case config.Log == nil:
		return nil, nil, fmt.Errorf("%w: logger required", runtime.ErrInvalidConfig)
	case config.Stderr == nil, config.Stdout == nil:
		return nil, nil, fmt.Errorf("%w: stderr and stdout required", runtime.ErrInvalidConfig)
	}

	intitializer := newInitializer(cmd.Path)

	server := grpcutils.NewServer()
	defer server.GracefulStop()
	pb.RegisterRuntimeServer(server, gruntime.NewServer(intitializer))

	go grpcutils.Serve(listener, server)

	serverAddr := listener.Addr()
	// CRITICAL: If cmd.Env is already set (e.g., by tests), preserve those values
	// and only add our required environment variable. If cmd.Env is nil,
	// copy the parent's environment first.
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", runtime.EngineAddressKey, serverAddr.String()))

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// start subprocess
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("failed to start process: %w", err)
	}

	log := config.Log
	stopper := NewStopper(log, cmd)

	// start stdout collector
	go func() {
		_, err := io.Copy(config.Stdout, stdoutPipe)
		if err != nil {
			log.Error("stdout collector failed", "error", err)
		}
		stopper.Stop(context.TODO())

		log.Info("stdout collector shutdown")
	}()

	// start stderr collector
	go func() {
		_, err := io.Copy(config.Stderr, stderrPipe)
		if err != nil {
			log.Error("stderr collector failed", "error", err)
		}
		stopper.Stop(context.TODO())

		log.Info("stderr collector shutdown")
	}()

	// wait for handshake success
	timeout := time.NewTimer(config.HandshakeTimeout)
	defer timeout.Stop()

	select {
	case <-intitializer.initialized:
	case <-timeout.C:
		stopper.Stop(ctx)
		return nil, nil, fmt.Errorf("%w: %w", runtime.ErrHandshakeFailed, runtime.ErrProcessNotFound)
	}

	if intitializer.err != nil {
		stopper.Stop(ctx)
		return nil, nil, fmt.Errorf("%w: %w", runtime.ErrHandshakeFailed, intitializer.err)
	}

	log.Info("plugin handshake succeeded", "addr", intitializer.vmAddr)

	status := &Status{
		Pid:  cmd.Process.Pid,
		Addr: intitializer.vmAddr,
	}
	return status, stopper, nil
}
