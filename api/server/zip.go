// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Serving a zip app on this router.
//
// A zip app owns a listener: zip.Serve is what starts one, and it is also what
// installs the projections of the app's typed ops — the OpenAPI document, the
// docs page, the MCP door, the op-call plane. Taking the app's request handler
// any other way serves the ops and none of the rest, and zip exports no verb
// that installs them without serving.
//
// So the app IS served, on a transport whose wire is the listener this process
// already has: zip hands the transport the app's request handler, the transport
// parks instead of binding, and Mount copies each net/http request onto it. The
// copy is written out because fasthttp ships the other direction only
// (fasthttpadaptor.NewFastHTTPHandler). It costs one request-sized copy per
// call, which an API route can afford.

package server

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/zap-proto/zip"
)

// Ops is the endpoint an app of typed operations is mounted at, beneath the base
// its service already answers on: /v1/info/ops, /v1/chain/P/ops.
//
// It is an endpoint rather than the base itself because [router.forceAddRouter]
// records a prefix mount ONLY for a non-empty endpoint — a handler at the base
// owns that exact path and nothing beneath it, so an app mounted there would
// serve neither its operations nor its document. One name for it, here, so every
// service on the node is reachable the same way.
const Ops = "/ops"

// mount is the address scheme of the transport below. An address under it names
// a mount waiting for its handler, not a socket.
const mount = "mount"

var (
	// waiting maps a mount address to the channel its handler arrives on, and
	// counting names each one, so two apps mounted at once cannot collide.
	waiting  sync.Map
	counting atomic.Uint64
)

func init() {
	zip.RegisterTransport(mount, zip.Transport{
		Serve: func(addr string, h fasthttp.RequestHandler) zip.Server {
			if ch, ok := waiting.LoadAndDelete(addr); ok {
				ch.(chan fasthttp.RequestHandler) <- h
			}
			return &parked{stop: make(chan struct{})}
		},
	})
}

// parked is a listener that never binds. The handler has already gone to Mount;
// this is what keeps zip's serving goroutine alive until the app shuts down.
type parked struct {
	stop chan struct{}
	once sync.Once
}

func (p *parked) ListenAndServe() error { <-p.stop; return nil }
func (p *parked) Close() error          { p.once.Do(func() { close(p.stop) }); return nil }

// Mount serves app and hands back its net/http face, ready for AddRoute.
//
// It installs [Authorize] before it serves, and the ordering is the whole
// point. zip raises an MCP door on any app holding a typed op, and an app with
// no Authorizer answers whoever knocks — so a mount that had to REMEMBER to
// authorize would eventually be a mount that forgot. Here, forgetting means not
// mounting: this is the only verb that puts a zip app on the node's router, so
// every app on it is under the rule by construction rather than by review.
func Mount(app *zip.App) (http.Handler, error) {
	app.Authorize(Authorize)

	at := strconv.FormatUint(counting.Add(1), 10)
	arrived := make(chan fasthttp.RequestHandler, 1)
	waiting.Store(at, arrived)
	defer waiting.Delete(at)

	if _, err := zip.Serve(app, mount+"://"+at); err != nil {
		return nil, err
	}
	// Serve starts the listeners on a goroutine and returns, so the handler
	// arrives immediately after. Bounded anyway: a wait that cannot end is a
	// boot that hangs with nothing to read.
	select {
	case h := <-arrived:
		return answer(h), nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("zip app mounted at %s never reached its transport", at)
	}
}

// answer copies a net/http request onto a fasthttp handler, and its reply back.
func answer(h fasthttp.RequestHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req fasthttp.Request
		req.Header.SetMethod(r.Method)
		req.SetRequestURI(r.URL.RequestURI())
		req.SetHost(r.Host)
		for name, values := range r.Header {
			for _, value := range values {
				req.Header.Add(name, value)
			}
		}
		if r.Body != nil {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			req.SetBody(body)
		}

		var ctx fasthttp.RequestCtx
		ctx.Init(&req, peer(r.RemoteAddr), nil)
		h(&ctx)

		header := w.Header()
		for name, value := range ctx.Response.Header.All() {
			// Content-Length and Connection describe THIS hop, and this hop is
			// net/http's: the whole body is written below, so it computes both.
			switch string(name) {
			case fasthttp.HeaderContentLength, fasthttp.HeaderConnection:
			default:
				header.Add(string(name), string(value))
			}
		}
		w.WriteHeader(ctx.Response.StatusCode())
		_, _ = w.Write(ctx.Response.Body())
	})
}

// peer reads the caller's address back off the request. nil when it does not
// parse — fasthttp substitutes a zero address, which is what an unknown peer is.
func peer(addr string) net.Addr {
	a, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil
	}
	return a
}
