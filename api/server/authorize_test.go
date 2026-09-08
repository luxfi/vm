// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zap-proto/zip"
)

// A security control is worth exactly what its absence costs, so this file
// measures the absence. Every case below runs the SAME call against the SAME
// mounted app twice — once as [Mount] leaves it, once with the Authorizer
// cleared — and asserts the two answers differ. Delete the install in Mount and
// the first half of every pair goes red; that is the whole test.
//
// Asserting only "it refused" would pass with the control gone, because an
// operation can be refused for half a dozen other reasons. Asserting the pair
// cannot.

type level struct {
	Level string `json:"level"`
}

type signed struct {
	Tx string `json:"tx"`
}

type height struct {
	Height uint64 `json:"height"`
}

// offBox and onBox are what the SOCKET said, which is the only thing the rule
// reads — there is no header here for a caller to state either with.
const (
	offBox = "203.0.113.9:52000"
	onBox  = "127.0.0.1:52000"
)

// node builds one app carrying an operation of each tier and mounts it the way
// the node does. ran reports whether the CHANGE actually executed, which is the
// fact a status code only stands in for.
func node(t *testing.T) (http.Handler, *zip.App, *bool) {
	t.Helper()

	ran := new(bool)
	app := zip.New(zip.Config{AppName: "node", DisableStartupMessage: true})

	// A change to the node. Operator tier by the rule, and by nothing else: it
	// is not named anywhere, it is simply not a read and not the relay.
	zip.Post(app, "/level", func(context.Context, *level) (*struct{}, error) {
		*ran = true
		return &struct{}{}, nil
	}, zip.WithOperationID("admin.setLoggerLevel"))

	// A read.
	zip.Get(app, "/height", func(context.Context, *struct{}) (*height, error) {
		return &height{Height: 7}, nil
	}, zip.WithOperationID("platform.getHeight"))

	// Already-signed bytes, handed to consensus.
	zip.Post(app, Relay, func(context.Context, *signed) (*struct{}, error) {
		return &struct{}{}, nil
	}, zip.WithOperationID("platform.issueTx"))

	handler, err := Mount(app)
	require.NoError(t, err)
	t.Cleanup(func() { _ = app.Shutdown() })
	return handler, app, ran
}

// call drives one request through the mounted handler as if it arrived from
// `from`, and reports the status and the body.
func call(t *testing.T, h http.Handler, from, method, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = from
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// TestAChangeFromOffBoxIsRefusedONLYBecauseMountInstalledTheRule is the
// mutation proof for REST: the same POST from the same address succeeds when
// the Authorizer is gone and is refused when it is there.
func TestAChangeFromOffBoxIsRefusedONLYBecauseMountInstalledTheRule(t *testing.T) {
	require := require.New(t)
	handler, app, ran := node(t)

	*ran = false
	code, body := call(t, handler, offBox, http.MethodPost, "/level", `{"level":"debug"}`)
	require.Equal(http.StatusForbidden, code, "an anonymous change reached the node")
	require.Contains(body, Refused)
	require.False(*ran, "the handler ran on a refused call")

	// THE MUTATION. zip reads app.authorizer at each invoke and documents that a
	// nil one leaves every op open, so clearing it removes this control and
	// nothing else: same app, same handler, same request, same address.
	app.Authorize(nil)

	*ran = false
	code, body = call(t, handler, offBox, http.MethodPost, "/level", `{"level":"debug"}`)
	require.Equal(http.StatusOK, code, "without the Authorizer this call must succeed — otherwise the refusal above proves nothing about the rule")
	require.True(*ran, "the change did not execute, so the pair measures something other than authorization: %s", body)
}

// TestTheSameRuleGatesTheMCPDoor is the same proof over MCP, which is the door
// this control exists for: zip serves one on every app with a typed op, and it
// is the surface an agent reaches with no credential at all.
func TestTheSameRuleGatesTheMCPDoor(t *testing.T) {
	require := require.New(t)
	handler, app, ran := node(t)

	tool := func() (bool, string) {
		t.Helper()
		*ran = false
		_, body := call(t, handler, offBox, http.MethodPost, "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"admin.setLoggerLevel","arguments":{"level":"debug"}}}`)
		var out struct {
			Result struct {
				IsError bool `json:"isError"`
			} `json:"result"`
		}
		require.NoError(json.Unmarshal([]byte(body), &out), body)
		return out.Result.IsError, body
	}

	isErr, body := tool()
	require.True(isErr, "MCP tools/call was answered for an anonymous caller: %s", body)
	require.False(*ran, "the handler ran on a refused tools/call")

	app.Authorize(nil)

	isErr, body = tool()
	require.False(isErr, "without the Authorizer the tool must run: %s", body)
	require.True(*ran, "the change did not execute over MCP, so this pair measures something other than authorization")
}

// TestTheOperatorIsAdmitted — the rule refuses a stranger, not everyone. An
// operator on the node's own machine is the caller http-host has always served.
func TestTheOperatorIsAdmitted(t *testing.T) {
	require := require.New(t)
	handler, _, ran := node(t)

	*ran = false
	code, body := call(t, handler, onBox, http.MethodPost, "/level", `{"level":"debug"}`)
	require.Equal(http.StatusOK, code, body)
	require.True(*ran)
}

// TestAReadAndARelayAnswerAnyone — the open tier, from off the box. A read
// changes nothing, and a transaction arrives already signed: the node holds no
// key that could have signed it, so consensus is what authorizes it and adding
// a second opinion here would only refuse valid traffic.
func TestAReadAndARelayAnswerAnyone(t *testing.T) {
	require := require.New(t)
	handler, _, _ := node(t)

	code, body := call(t, handler, offBox, http.MethodGet, "/height", "")
	require.Equal(http.StatusOK, code, body)
	require.JSONEq(`{"height":7}`, body)

	code, body = call(t, handler, offBox, http.MethodPost, Relay, `{"tx":"0xdeadbeef"}`)
	require.Equal(http.StatusOK, code, body)
}

// TestAPeerWithNoAddressIsNotTheOperator — the rule fails closed. fasthttp
// substitutes a zero address for a peer it cannot resolve, and a zero address
// is not this machine.
func TestAPeerWithNoAddressIsNotTheOperator(t *testing.T) {
	require.False(t, here(""))
	require.False(t, here("0.0.0.0"))
	require.False(t, here("not-an-address"))
	require.True(t, here("127.0.0.1"))
	require.True(t, here("::1"))
}

// TestAnUnreadablePeerIsNotTheOperator is the case that rewrote the rule. The
// transport under [Mount] reports NO address for a peer it cannot resolve, so
// a draft that admitted an addressless call as the node's own would have
// admitted an unreadable one too — a fail-open on exactly the input an attacker
// controls least well and a proxy mangles most easily. It is one admitting
// clause now, and an address that does not read is refused like any stranger.
func TestAnUnreadablePeerIsNotTheOperator(t *testing.T) {
	require := require.New(t)
	handler, _, ran := node(t)

	for _, from := range []string{"", "garbage", "@", "0.0.0.0:0"} {
		*ran = false
		code, body := call(t, handler, from, http.MethodPost, "/level", `{"level":"debug"}`)
		require.Equal(http.StatusForbidden, code, "a peer of %q was admitted as the operator: %s", from, body)
		require.False(*ran, "the handler ran for a peer of %q", from)
	}

	// And a read still answers, from an address or from none: refusing the
	// unreadable is about authority, not about reachability.
	code, body := call(t, handler, "garbage", http.MethodGet, "/height", "")
	require.Equal(http.StatusOK, code, body)
}

// TestAComposedOpIsAuthorizedToo — zip binds an op's authorizer to the App the
// op was REGISTERED on, not to the app that is serving (zip typed.go:423,457),
// so an app assembled out of parts is where this rule would silently stop
// covering. Mount is handed the whole assembly; this asserts the parts are
// under it too, and goes red if that ever stops being true.
func TestAComposedOpIsAuthorizedToo(t *testing.T) {
	require := require.New(t)

	ran := false
	part := zip.New(zip.Config{AppName: "part", DisableStartupMessage: true})
	zip.Post(part, "/level", func(context.Context, *level) (*struct{}, error) {
		ran = true
		return &struct{}{}, nil
	}, zip.WithOperationID("part.setLoggerLevel"))

	whole := zip.New(zip.Config{AppName: "whole", DisableStartupMessage: true})
	whole.Use(part)

	handler, err := Mount(whole)
	require.NoError(err)
	t.Cleanup(func() { _ = whole.Shutdown() })

	code, body := call(t, handler, offBox, http.MethodPost, "/level", `{"level":"debug"}`)
	require.Equal(http.StatusForbidden, code, "a composed op answered an anonymous change: %s", body)
	require.Contains(body, Refused)
	require.False(ran, "the composed handler ran on a refused call")
}
