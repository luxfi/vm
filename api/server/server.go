// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/cors"
	zaphttp "github.com/zap-proto/http"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/luxfi/constants"
	"github.com/luxfi/ids"
	log "github.com/luxfi/log"
	"github.com/luxfi/metric"
	"github.com/luxfi/runtime"
	"github.com/luxfi/trace"
	"github.com/luxfi/vm"
	"github.com/luxfi/vm/api"
)

const (
	// baseURL is the canonical — and only — prefix for every luxd HTTP route
	// (/v1/chain/C/rpc, /v1/info, /v1/health, ...). Single source of truth:
	// AddRoute/AddAliases and the root/health helpers in router.go all derive
	// their paths from it. The legacy /ext prefix is gone;
	// one way, no backward compatibility (activation Dec 25 2025).
	baseURL = "/v1"

	maxConcurrentStreams = 64
)

// Chain is where a chain answers, and the one place that address is built.
//
// uri is a node's base URL, or empty for a path on this node: Chain("", "P")+Ops
// is /v1/chain/P/ops. The segment is [constants.ChainAliasPrefix], named once,
// so every caller moves with it. That is the point of routing them all through
// here: when the segment last changed, the clients that spelled it by hand went
// on pointing at the name the router had already left behind.
func Chain(uri, alias string) string {
	return uri + baseURL + "/" + constants.ChainAliasPrefix + "/" + alias
}

var (
	_ PathAdder = readPathAdder{}
	_ Server    = (*server)(nil)
)

type PathAdder interface {
	// AddRoute registers a route to a handler.
	AddRoute(handler http.Handler, base, endpoint string) error

	// AddAliases registers aliases to the server
	AddAliases(endpoint string, aliases ...string) error
}

type PathAdderWithReadLock interface {
	// AddRouteWithReadLock registers a route to a handler assuming the http
	// read lock is currently held.
	AddRouteWithReadLock(handler http.Handler, base, endpoint string) error

	// AddAliasesWithReadLock registers aliases to the server assuming the http read
	// lock is currently held.
	AddAliasesWithReadLock(endpoint string, aliases ...string) error
}

// Server maintains the HTTP router
type Server interface {
	PathAdder
	PathAdderWithReadLock
	// Dispatch starts the API server
	Dispatch() error
	// RegisterChain registers the API endpoints associated with this chain.
	// That is, add <route, handler> pairs to server so that API calls can be
	// made to the VM.
	RegisterChain(chainName string, rt *runtime.Runtime, vm vm.VM)
	// Shutdown this server
	Shutdown() error
	// SetRootInfoProvider sets the provider for root endpoint information
	SetRootInfoProvider(provider RootInfoProvider)
}

type HTTPConfig struct {
	ReadTimeout       time.Duration `json:"readTimeout"`
	ReadHeaderTimeout time.Duration `json:"readHeaderTimeout"`
	WriteTimeout      time.Duration `json:"writeHeaderTimeout"`
	IdleTimeout       time.Duration `json:"idleTimeout"`
}

type server struct {
	// log this server writes to
	log log.Logger

	shutdownTimeout time.Duration

	tracingEnabled bool
	tracer         trace.Tracer

	metrics *serverMetrics

	// Maps endpoints to handlers
	router *router

	srv *http.Server

	// Listener used to serve traffic
	listener net.Listener

	// handler is the fully-wrapped API handler chain (CORS + host-filter +
	// /v1/* router). Held here so the optional ZAP-RPC listener serves the
	// exact same handler as the HTTP listener.
	handler http.Handler

	// zapSrv is the optional ZAP-RPC listener; nil unless ZAP_RPC_LISTEN
	// is set. See zap_listener.go.
	zapSrv *zaphttp.Server
}

// New returns an instance of a Server.
func New(
	log log.Logger,
	listener net.Listener,
	allowedOrigins []string,
	shutdownTimeout time.Duration,
	nodeID ids.NodeID,
	tracingEnabled bool,
	tracer trace.Tracer,
	registerer metric.Registerer,
	httpConfig HTTPConfig,
	allowedHosts []string,
) (Server, error) {
	m, err := newMetrics(registerer)
	if err != nil {
		return nil, err
	}

	router := newRouter()
	handler := wrapHandler(router, nodeID, allowedOrigins, allowedHosts)

	httpServer := &http.Server{
		Handler: h2c.NewHandler(
			handler,
			&http2.Server{
				MaxConcurrentStreams: maxConcurrentStreams,
			}),
		ReadTimeout:       httpConfig.ReadTimeout,
		ReadHeaderTimeout: httpConfig.ReadHeaderTimeout,
		WriteTimeout:      httpConfig.WriteTimeout,
		IdleTimeout:       httpConfig.IdleTimeout,
	}

	log.Info("API created with allowed origins: " + strings.Join(allowedOrigins, ","))

	return &server{
		log:             log,
		shutdownTimeout: shutdownTimeout,
		tracingEnabled:  tracingEnabled,
		tracer:          tracer,
		metrics:         m,
		router:          router,
		srv:             httpServer,
		listener:        listener,
		handler:         handler,
	}, nil
}

func (s *server) Dispatch() error {
	// Additively boot the ZAP-RPC listener (opt-in via ZAP_RPC_LISTEN).
	// Serves the same handler over github.com/zap-proto/http so the gateway
	// can reach luxd over the native ZAP mesh. Never fatal — HTTP serves
	// regardless.
	s.zapSrv = startZapRPCListener(s.log, s.handler, zapRPCListenAddr())
	return s.srv.Serve(s.listener)
}

func (s *server) RegisterChain(chainName string, rt *runtime.Runtime, vm vm.VM) {
	s.log.Debug("chain registered (handlers will be created by chain manager)",
		log.String("chainName", chainName),
		log.Stringer("chainID", rt.ChainID),
	)
}

func (s *server) AddRoute(handler http.Handler, base, endpoint string) error {
	return s.addRoute(handler, base, endpoint)
}

func (s *server) AddRouteWithReadLock(handler http.Handler, base, endpoint string) error {
	s.router.lock.RUnlock()
	defer s.router.lock.RLock()
	return s.addRoute(handler, base, endpoint)
}

func (s *server) addRoute(handler http.Handler, base, endpoint string) error {
	url := fmt.Sprintf("%s/%s", baseURL, base)
	s.log.Info("adding route",
		log.UserString("url", url),
		log.UserString("endpoint", endpoint),
	)

	if s.tracingEnabled {
		handler = api.TraceHandler(handler, url, s.tracer)
	}

	return s.router.AddRouter(url, endpoint, handler)
}

// StateGetter interface for getting chain state
type StateGetter interface {
	Get() vm.State
}

// Reject middleware wraps a handler. If the chain that the context describes is
// not done state-syncing/bootstrapping, writes back an error.
func rejectMiddleware(handler http.Handler, rt *runtime.Runtime) http.Handler {
	return handler
}

func (s *server) AddAliases(endpoint string, aliases ...string) error {
	url := fmt.Sprintf("%s/%s", baseURL, endpoint)
	endpoints := make([]string, len(aliases))
	for i, alias := range aliases {
		endpoints[i] = fmt.Sprintf("%s/%s", baseURL, alias)
	}
	return s.router.AddAlias(url, endpoints...)
}

func (s *server) AddAliasesWithReadLock(endpoint string, aliases ...string) error {
	// This is safe, as the read lock doesn't actually need to be held once the
	// http handler is called. However, it is unlocked later, so this function
	// must end with the lock held.
	s.router.lock.RUnlock()
	defer s.router.lock.RLock()

	return s.AddAliases(endpoint, aliases...)
}

func (s *server) Shutdown() error {
	if s.zapSrv != nil {
		_ = s.zapSrv.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	err := s.srv.Shutdown(ctx)
	cancel()

	// If shutdown times out, make sure the server is still shutdown.
	_ = s.srv.Close()
	return err
}

// SetRootInfoProvider sets the provider for root endpoint information
func (s *server) SetRootInfoProvider(provider RootInfoProvider) {
	s.router.SetRootInfoProvider(provider)
}

type readPathAdder struct {
	pather PathAdderWithReadLock
}

func PathWriterFromWithReadLock(pather PathAdderWithReadLock) PathAdder {
	return readPathAdder{
		pather: pather,
	}
}

func (a readPathAdder) AddRoute(handler http.Handler, base, endpoint string) error {
	return a.pather.AddRouteWithReadLock(handler, base, endpoint)
}

func (a readPathAdder) AddAliases(endpoint string, aliases ...string) error {
	return a.pather.AddAliasesWithReadLock(endpoint, aliases...)
}

func wrapHandler(
	handler http.Handler,
	nodeID ids.NodeID,
	allowedOrigins []string,
	allowedHosts []string,
) http.Handler {
	h := filterInvalidHosts(handler, allowedHosts)
	h = cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowCredentials: true,
	}).Handler(h)
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// Attach this node's ID as a header
			w.Header().Set("node-id", nodeID.String())
			h.ServeHTTP(w, r)
		},
	)
}
