// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package dag provides RPC infrastructure for DAG-based VMs (DAGVM).
// This implements the server and client for VMs that use vertices with multiple parents.
package dag

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"

	"github.com/luxfi/atomic"
	"github.com/luxfi/log"
	"github.com/luxfi/version"
	"github.com/luxfi/vm/rpc/grpcutils"
	"github.com/luxfi/vm/rpc/gruntime"
	"github.com/luxfi/vm/rpc/runtime"

	dagpb "github.com/luxfi/vm/proto/pb/dag"
	runtimepb "github.com/luxfi/node/proto/pb/vm/runtime"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const defaultRuntimeDialTimeout = 5 * time.Second

// Serve starts the RPC DAG VM server and performs a handshake with the VM runtime service.
// The address of the Runtime server is expected to be passed via ENV `runtime.EngineAddressKey`.
// This address is used by the Runtime client to send Initialize RPC to server.
func Serve(ctx context.Context, log log.Logger, vm DAGVM, opts ...grpcutils.ServerOption) error {
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	var allowShutdown atomic.Atomic[bool]
	server := newVMServer(vm, &allowShutdown, opts...)
	go func(ctx context.Context) {
		defer func() {
			server.GracefulStop()
			log.Info("dag vm server: graceful termination success")
		}()

		for {
			select {
			case s := <-signals:
				// We drop all signals until our parent process has notified us
				// that we are shutting down. Once we are in the shutdown
				// workflow, we will gracefully exit upon receiving a SIGTERM.
				if !allowShutdown.Get() {
					log.Debug("dag runtime engine: ignoring signal", "signal", s)
					continue
				}

				switch s {
				case syscall.SIGINT:
					log.Debug("dag runtime engine: ignoring signal", "signal", s)
				case syscall.SIGTERM:
					log.Info("dag runtime engine: received shutdown signal", "signal", s)
					return
				}
			case <-ctx.Done():
				log.Info("dag runtime engine: context has been cancelled")
				return
			}
		}
	}(ctx)

	// address of Runtime server from ENV
	log.Info("dag.Serve: getting runtime address from env", "key", runtime.EngineAddressKey)
	runtimeAddr := os.Getenv(runtime.EngineAddressKey)
	if runtimeAddr == "" {
		return fmt.Errorf("required env var missing: %q", runtime.EngineAddressKey)
	}
	log.Info("dag.Serve: runtime address obtained", "addr", runtimeAddr)

	log.Info("dag.Serve: dialing runtime server", "addr", runtimeAddr)
	clientConn, err := grpcutils.Dial(runtimeAddr)
	if err != nil {
		return fmt.Errorf("failed to create client conn: %w", err)
	}
	log.Info("dag.Serve: dial succeeded, creating runtime client")

	client := gruntime.NewClient(runtimepb.NewRuntimeClient(clientConn))
	log.Info("dag.Serve: creating gRPC listener")

	listener, err := grpcutils.NewListener()
	if err != nil {
		return fmt.Errorf("failed to create new listener: %w", err)
	}
	log.Info("dag.Serve: listener created", "addr", listener.Addr().String())

	log.Info("dag.Serve: calling client.Initialize",
		"protocol", version.RPCDAGVMProtocol,
		"listenerAddr", listener.Addr().String(),
	)

	log.Debug("initializing dag vm runtime",
		"protocol", version.RPCDAGVMProtocol,
		"addr", listener.Addr().String(),
	)

	ctx, cancel := context.WithTimeout(ctx, defaultRuntimeDialTimeout)
	defer cancel()
	err = client.Initialize(ctx, version.RPCDAGVMProtocol, listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("failed to initialize dag vm runtime: %w", err)
	}

	log.Info("dag vm runtime initialized successfully", "addr", listener.Addr().String())

	// start RPC DAG VM server
	grpcutils.Serve(listener, server)

	return nil
}

// newVMServer returns an RPC DAG VM server serving health and VM services.
func newVMServer(vm DAGVM, allowShutdown *atomic.Atomic[bool], opts ...grpcutils.ServerOption) *grpc.Server {
	server := grpcutils.NewServer(opts...)
	dagpb.RegisterDAGVMServer(server, NewServer(vm, allowShutdown))

	health := health.NewServer()
	health.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, health)

	return server
}
