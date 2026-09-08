// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// ZAP-RPC listener — serves the EXACT same fully-wrapped API handler chain
// (CORS + host-filter + /v1/* router) as the HTTP listener, but over the
// github.com/zap-proto/http binary protocol. This is what makes luxd a
// first-class citizen of the ZAP service mesh: the api.<brand> gateway can
// proxy to luxd over native ZAP instead of HTTP/1.1.
//
// Purely ADDITIVE and OPT-IN: the existing HTTP path is untouched. The ZAP
// listener only boots when ZAP_RPC_LISTEN is set to a non-empty bind
// address (e.g. ":9651"); unset/"off" means it never starts, so existing
// deployments are byte-for-byte unaffected. Boot failures are WARNED, never
// fatal — the node must keep serving HTTP even if the ZAP listener fails.

package server

import (
	"net/http"
	"os"

	"github.com/valyala/fasthttp/fasthttpadaptor"
	zaphttp "github.com/zap-proto/http"

	log "github.com/luxfi/log"
)

// envZapRPCListen is the env var that sets the ZAP-RPC bind address.
// Empty / unset / "off" (case-insensitive) keeps the listener disabled.
const envZapRPCListen = "ZAP_RPC_LISTEN"

// zapRPCListenAddr returns the configured bind address, or "" if the ZAP-RPC
// listener should stay disabled. Disabled is the default — the listener is
// strictly opt-in so a node upgrade never silently opens a new port.
func zapRPCListenAddr() string {
	v, ok := os.LookupEnv(envZapRPCListen)
	if !ok {
		return ""
	}
	switch v {
	case "", "off", "OFF", "Off", "false", "0":
		return ""
	default:
		return v
	}
}

// startZapRPCListener boots a ZAP-RPC listener serving handler in a goroutine
// and returns the server (nil if disabled). The same handler instance the
// HTTP server uses is served, so the two transports are behaviourally
// identical — only the wire encoding differs. Boot errors are logged at
// Warning and never propagated; the HTTP path must keep serving regardless.
func startZapRPCListener(logger log.Logger, handler http.Handler, addr string) *zaphttp.Server {
	if addr == "" {
		return nil
	}
	// zap-proto/http >= v0.2.0 takes a fasthttp.RequestHandler. Adapt the very
	// same net/http handler chain the HTTP listener serves, so the two
	// transports stay behaviourally identical — only the wire encoding differs.
	srv := &zaphttp.Server{Addr: addr, Handler: fasthttpadaptor.NewFastHTTPHandler(handler)}
	go func() {
		logger.Info("ZAP-RPC API listening", log.UserString("addr", addr))
		if err := srv.ListenAndServe(); err != nil {
			logger.Warn("ZAP-RPC listener exited", log.Err(err))
		}
	}()
	return srv
}
