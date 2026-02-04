//go:build grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

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
	"github.com/luxfi/vm/chain"
	"github.com/luxfi/vm/rpc/grpcutils"
	"github.com/luxfi/vm/rpc/gruntime"
	"github.com/luxfi/vm/rpc/runtime"

	vmpb "github.com/luxfi/node/proto/pb/vm"
	runtimepb "github.com/luxfi/node/proto/pb/vm/runtime"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const defaultRuntimeDialTimeout = 5 * time.Second

// The address of the Runtime server is expected to be passed via ENV `runtime.EngineAddressKey`.
// This address is used by the Runtime client to send Initialize RPC to server.
//
// Serve starts the RPC Chain VM server and performs a handshake with the VM runtime service.
func Serve(ctx context.Context, log log.Logger, vm chain.ChainVM, opts ...grpcutils.ServerOption) error {
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	var allowShutdown atomic.Atomic[bool]
	server := newVMServer(vm, &allowShutdown, opts...)
	go func(ctx context.Context) {
		defer func() {
			server.GracefulStop()
			log.Info("vm server: graceful termination success")
		}()

		for {
			select {
			case s := <-signals:
				// We drop all signals until our parent process has notified us
				// that we are shutting down. Once we are in the shutdown
				// workflow, we will gracefully exit upon receiving a SIGTERM.
				if !allowShutdown.Get() {
					log.Debug("runtime engine: ignoring signal", "signal", s)
					continue
				}

				switch s {
				case syscall.SIGINT:
					log.Debug("runtime engine: ignoring signal", "signal", s)
				case syscall.SIGTERM:
					log.Info("runtime engine: received shutdown signal", "signal", s)
					return
				}
			case <-ctx.Done():
				log.Info("runtime engine: context has been cancelled")
				return
			}
		}
	}(ctx)

	// File-based debug logging
	debugFile := func(msg string) {
		if f, err := os.OpenFile("/tmp/evm_serve.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			fmt.Fprintf(f, "[%d] %s\n", os.Getpid(), msg)
			f.Close()
		}
	}
	debugFile("Serve() starting")

	// address of Runtime server from ENV
	log.Info("rpcchainvm.Serve: getting runtime address from env", "key", runtime.EngineAddressKey)
	debugFile("Getting env var: " + runtime.EngineAddressKey)
	runtimeAddr := os.Getenv(runtime.EngineAddressKey)
	debugFile("Got runtimeAddr: " + runtimeAddr)
	if runtimeAddr == "" {
		debugFile("ERROR: env var missing")
		return fmt.Errorf("required env var missing: %q", runtime.EngineAddressKey)
	}
	log.Info("rpcchainvm.Serve: runtime address obtained", "addr", runtimeAddr)
	debugFile("Runtime address obtained: " + runtimeAddr)

	log.Info("rpcchainvm.Serve: dialing runtime server", "addr", runtimeAddr)
	debugFile("Dialing runtime server: " + runtimeAddr)
	clientConn, err := grpcutils.Dial(runtimeAddr)
	if err != nil {
		debugFile("ERROR dial failed: " + err.Error())
		return fmt.Errorf("failed to create client conn: %w", err)
	}
	log.Info("rpcchainvm.Serve: dial succeeded, creating runtime client")
	debugFile("Dial succeeded")

	debugFile("Creating gruntime client")
	client := gruntime.NewClient(runtimepb.NewRuntimeClient(clientConn))
	debugFile("gruntime client created")
	log.Info("rpcchainvm.Serve: creating gRPC listener")

	debugFile("Creating gRPC listener")
	listener, err := grpcutils.NewListener()
	if err != nil {
		debugFile("ERROR creating listener: " + err.Error())
		return fmt.Errorf("failed to create new listener: %w", err)
	}
	debugFile("Listener created: " + listener.Addr().String())
	log.Info("rpcchainvm.Serve: listener created", "addr", listener.Addr().String())

	log.Info("rpcchainvm.Serve: calling client.Initialize",
		"protocol", version.RPCChainVMProtocol,
		"listenerAddr", listener.Addr().String(),
	)

	log.Debug("initializing vm runtime",
		"protocol", version.RPCChainVMProtocol,
		"addr", listener.Addr().String(),
	)

	debugFile(fmt.Sprintf("Calling client.Initialize(protocol=%d, addr=%s)", version.RPCChainVMProtocol, listener.Addr().String()))
	ctx, cancel := context.WithTimeout(ctx, defaultRuntimeDialTimeout)
	defer cancel()
	err = client.Initialize(ctx, version.RPCChainVMProtocol, listener.Addr().String())
	if err != nil {
		debugFile("ERROR Initialize failed: " + err.Error())
		_ = listener.Close()
		return fmt.Errorf("failed to initialize vm runtime: %w", err)
	}
	debugFile("Initialize succeeded")

	log.Info("vm runtime initialized successfully", "addr", listener.Addr().String())

	// start RPC Chain VM server
	debugFile("Starting grpcutils.Serve (this should block indefinitely)")
	grpcutils.Serve(listener, server)
	debugFile("grpcutils.Serve returned - THIS IS UNEXPECTED unless shutting down")

	return nil
}

// Returns an RPC Chain VM server serving health and VM services.
func newVMServer(vm chain.ChainVM, allowShutdown *atomic.Atomic[bool], opts ...grpcutils.ServerOption) *grpc.Server {
	server := grpcutils.NewServer(opts...)
	vmpb.RegisterVMServer(server, NewServer(vm, allowShutdown))

	health := health.NewServer()
	health.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, health)

	return server
}
