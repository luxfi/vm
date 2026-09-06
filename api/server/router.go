// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package server

import (
	"errors"
	"fmt"
	"net/http"
	"path"
	"sync"

	"github.com/go-json-experiment/json"

	apitypes "github.com/luxfi/api/types"
	"github.com/luxfi/math/set"
)

const HTTPHeaderRoute = apitypes.HTTPHeaderRoute

var (
	errUnknownBaseURL  = errors.New("unknown base url")
	errUnknownEndpoint = errors.New("unknown endpoint")
	errAlreadyReserved = errors.New("route is either already aliased or already maps to a handle")
)

// RootInfo contains information returned at the root endpoint
type RootInfo struct {
	NodeID    string `json:"nodeId,omitempty"`
	NetworkID uint32 `json:"networkId,omitempty"`
	Version   string `json:"version,omitempty"`
	Ready     bool   `json:"ready"`
	Chains    struct {
		C string `json:"c"`
		P string `json:"p"`
		X string `json:"x"`
	} `json:"chains"`
	Endpoints struct {
		RPC       string `json:"rpc"`
		Websocket string `json:"ws"`
		Info      string `json:"info"`
		Health    string `json:"health"`
	} `json:"endpoints"`
}

// RootInfoProvider provides node information for the root endpoint
type RootInfoProvider interface {
	GetRootInfo() RootInfo
}

type router struct {
	lock sync.RWMutex

	routeLock      sync.Mutex
	reservedRoutes set.Set[string]     // Reserves routes so that there can't be alias that conflict
	aliases        map[string][]string // Maps a route to a set of reserved routes
	// headerRoutes contains routes based on http headers
	// aliasing is not currently supported
	headerRoutes map[string]http.Handler
	// legacy url-based routing
	routes map[string]map[string]http.Handler // Maps routes to a handler
	// paths maps a full url (base+endpoint) to the handler registered at
	// exactly that path. Every endpoint appears here.
	paths map[string]http.Handler
	// mounts maps a full endpoint url (base+endpoint) to its handler. A base is
	// a namespace shared by sibling endpoints; an endpoint is a mount, and it
	// owns the paths beneath it. Only non-empty endpoints appear here.
	mounts map[string]http.Handler

	// rootInfoProvider provides node information for GET /
	rootInfoProvider RootInfoProvider
}

func newRouter() *router {
	return &router{
		reservedRoutes: make(set.Set[string]),
		aliases:        make(map[string][]string),
		headerRoutes:   make(map[string]http.Handler),
		routes:         make(map[string]map[string]http.Handler),
		paths:          make(map[string]http.Handler),
		mounts:         make(map[string]http.Handler),
	}
}

// serveBelowMount answers a request that matched no exact route by handing it
// to the endpoint it lives under, with the mount stripped off.
//
// A VM names the paths it serves relative to its own mount — zkvm's
// /getStatus, aivm's /providers — because it cannot know the chain id the node
// will mount it at. Mounted as a leaf, the handler was only ever reached at the
// mount path itself, read that absolute path as its own, matched none of its
// routes and answered 404. Z-Chain and A-Chain ran, finalized blocks and
// reported metrics while serving nothing.
//
// Exact routes are matched first by construction, so an endpoint can never
// shadow a sibling.
func (r *router) serveBelowMount(writer http.ResponseWriter, request *http.Request) {
	path := request.URL.Path
	for i := len(path) - 1; i > 0; i-- {
		if path[i] != '/' {
			continue
		}
		mount := path[:i]
		r.routeLock.Lock()
		handler, ok := r.mounts[mount]
		r.routeLock.Unlock()
		if ok {
			http.StripPrefix(mount, handler).ServeHTTP(writer, request)
			return
		}
	}
	http.NotFound(writer, request)
}

// servePath dispatches on the URL: the canonical spelling of the path, then
// the route registered at exactly that path, then the endpoint it lives under.
//
// A doubled separator or a dot segment names a place the client could have
// named plainly, so it is sent to the plain name rather than served at two
// addresses. A trailing slash is not noise and is kept — /rpc is the mount
// and /rpc/ is the root beneath it, which are two different requests.
func (r *router) servePath(writer http.ResponseWriter, request *http.Request) {
	if clean := canonical(request.URL.Path); clean != request.URL.Path {
		here := *request.URL
		here.Path = clean
		writer.Header().Set("Location", here.String())
		writer.WriteHeader(http.StatusMovedPermanently)
		return
	}

	r.routeLock.Lock()
	handler, ok := r.paths[request.URL.Path]
	r.routeLock.Unlock()
	if ok {
		handler.ServeHTTP(writer, request)
		return
	}
	r.serveBelowMount(writer, request)
}

// canonical is path.Clean with the trailing slash left on.
func canonical(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	clean := path.Clean(p)
	if clean != "/" && p[len(p)-1] == '/' {
		clean += "/"
	}
	return clean
}

func (r *router) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	// Handle root "/" specially for EVM compatibility
	if request.URL.Path == "/" {
		r.handleRoot(writer, request)
		return
	}

	// /healthz — the platform-standard liveness address, and an alias for
	// /v1/health/ops/liveness rather than an answer of its own. A probe that
	// computes its own verdict is a probe that can disagree with the node.
	if request.URL.Path == "/healthz" {
		alias := request.Clone(request.Context())
		alias.URL.Path = baseURL + "/health" + Ops + "/liveness"
		r.servePath(writer, alias)
		return
	}

	route, ok := request.Header[HTTPHeaderRoute]
	if !ok {
		// If there is no routing header, fall-back to the legacy path-based
		// routing
		r.servePath(writer, request)
		return
	}

	// Request specified the routing header key but did not provide a
	// corresponding value
	if len(route) != 1 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	handler, ok := r.headerRoutes[route[0]]
	if !ok {
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	handler.ServeHTTP(writer, request)
}

// handleRoot handles requests to "/" - GET returns node info, POST proxies to C-chain RPC
func (r *router) handleRoot(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		r.handleRootGET(w, req)
	case http.MethodPost:
		r.handleRootPOST(w, req)
	case http.MethodOptions:
		// CORS preflight
		w.Header().Set("Allow", "GET, POST, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "Method not allowed. Use GET for node info or POST for EVM JSON-RPC.", http.StatusMethodNotAllowed)
	}
}

// handleRootGET returns node information as JSON
func (r *router) handleRootGET(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var info RootInfo
	if r.rootInfoProvider != nil {
		info = r.rootInfoProvider.GetRootInfo()
	} else {
		// Default info when provider not set
		info = RootInfo{
			Ready: true,
			Chains: struct {
				C string `json:"c"`
				P string `json:"p"`
				X string `json:"x"`
			}{
				C: Chain("", "C") + "/rpc",
				P: Chain("", "P"),
				X: Chain("", "X"),
			},
			Endpoints: struct {
				RPC       string `json:"rpc"`
				Websocket string `json:"ws"`
				Info      string `json:"info"`
				Health    string `json:"health"`
			}{
				RPC:       Chain("", "C") + "/rpc",
				Websocket: Chain("", "C") + "/ws",
				Info:      baseURL + "/info",
				Health:    baseURL + "/health",
			},
		}
	}

	if err := json.MarshalWrite(w, info); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// handleRootPOST proxies JSON-RPC requests to the C-chain
func (r *router) handleRootPOST(w http.ResponseWriter, req *http.Request) {
	// Look up the C-chain RPC handler
	handler, err := r.GetHandler(Chain("", "C"), "/rpc")
	if err != nil {
		// Try alternate path formats
		handler, err = r.GetHandler(Chain("", "C")+"/rpc", "")
		if err != nil {
			// Return proper JSON-RPC error
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"C-chain not available"}}`))
			return
		}
	}

	// Forward the request to the C-chain handler
	handler.ServeHTTP(w, req)
}

// SetRootInfoProvider sets the provider for root endpoint information
func (r *router) SetRootInfoProvider(provider RootInfoProvider) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.rootInfoProvider = provider
}

// GetHandler is the handler registered at one base and endpoint.
func (r *router) GetHandler(base, endpoint string) (http.Handler, error) {
	r.routeLock.Lock()
	defer r.routeLock.Unlock()

	urlBase, exists := r.routes[base]
	if !exists {
		return nil, errUnknownBaseURL
	}
	handler, exists := urlBase[endpoint]
	if !exists {
		return nil, errUnknownEndpoint
	}
	return handler, nil
}

func (r *router) AddHeaderRoute(route string, handler http.Handler) bool {
	r.lock.Lock()
	defer r.lock.Unlock()

	_, ok := r.headerRoutes[route]
	if ok {
		return false
	}

	r.headerRoutes[route] = handler
	return true
}

func (r *router) AddRouter(base, endpoint string, handler http.Handler) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.routeLock.Lock()
	defer r.routeLock.Unlock()

	return r.addRouter(base, endpoint, handler)
}

func (r *router) addRouter(base, endpoint string, handler http.Handler) error {
	if r.reservedRoutes.Contains(base) {
		return fmt.Errorf("%w: %s", errAlreadyReserved, base)
	}

	return r.forceAddRouter(base, endpoint, handler)
}

func (r *router) forceAddRouter(base, endpoint string, handler http.Handler) error {
	endpoints := r.routes[base]
	if endpoints == nil {
		endpoints = make(map[string]http.Handler)
	}
	url := base + endpoint
	if _, exists := endpoints[endpoint]; exists {
		return fmt.Errorf("failed to create endpoint as %s already exists", url)
	}

	endpoints[endpoint] = handler
	r.routes[base] = endpoints
	if endpoint != "" {
		r.mounts[url] = handler
	}
	// A base and an endpoint can concatenate to a url another pair already
	// holds; the pair that got there first keeps it.
	if _, taken := r.paths[url]; !taken {
		r.paths[url] = handler
	}

	var err error
	if aliases, exists := r.aliases[base]; exists {
		for _, alias := range aliases {
			if innerErr := r.forceAddRouter(alias, endpoint, handler); err == nil {
				err = innerErr
			}
		}
	}
	return err
}

func (r *router) AddAlias(base string, aliases ...string) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.routeLock.Lock()
	defer r.routeLock.Unlock()

	for _, alias := range aliases {
		if r.reservedRoutes.Contains(alias) {
			return fmt.Errorf("%w: %s", errAlreadyReserved, alias)
		}
	}

	for _, alias := range aliases {
		r.reservedRoutes.Add(alias)
	}

	r.aliases[base] = append(r.aliases[base], aliases...)

	var err error
	if endpoints, exists := r.routes[base]; exists {
		for endpoint, handler := range endpoints {
			for _, alias := range aliases {
				if innerErr := r.forceAddRouter(alias, endpoint, handler); err == nil {
					err = innerErr
				}
			}
		}
	}
	return err
}
