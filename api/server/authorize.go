// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Who may call an operation on this node.
//
// [Authorize] is the node's authorization decision, and [Mount] installs it on
// every zip app the node serves, so an app cannot reach this router without it.
// It runs at zip's op-invoke seam — after the request is decoded into the op's
// typed input, before the handler runs, over REST and MCP alike (zip
// typed.go:451-470). One decision on one value, so the thing authorized is the
// thing executed: there is no second parse of the body for the two to disagree
// about.
//
// The seam rather than a route check, because zip serves an MCP door on every
// app that registers a typed op — "MCP is on by default — it's free" (zip
// mcp.go:50) — and an app with no Authorizer answers whoever walks in (zip
// authorize_test.go:114). Twelve chains answer on mainnet. Twelve doors would
// be twelve places to get a route check right; the seam is one place, and the
// thirteenth chain inherits it by being mounted.
//
// # Two tiers, and neither is a list
//
// ANYONE may read, and anyone may hand a chain bytes that are already signed.
// Neither asks the node for authority and the node has none to lend: it holds
// no key that could sign a transaction, so a submission carries its own
// authorization and consensus is what checks it.
//
// THE OPERATOR may change the node — its route table, its log levels, the
// chains it tracks, the files it writes. That authority is the operator's
// because the node is.
//
// Which tier an operation is in is READ off its registration rather than
// declared beside it. GET and HEAD are safe by definition (RFC 9110 §9.2.1):
// an operation that changes nothing has nothing to authorize. [Relay] is the
// one address at which a chain takes a write from an unauthenticated caller.
// Everything else changes the node.
//
// A list of privileged operations would be a second home for the truth and the
// one that drifts, so there is none: registering an operation cannot quietly
// open a hole, because nothing has to remember to close it.
//
// DISCLOSURE IS A DIFFERENT QUESTION and already has its own answer. A field
// the node may not hand out is marked `json:"-"` on the type that carries it —
// the staking key, the ML-DSA key, the KEM key (config/node/config.go:82-107).
// That is where what-may-be-seen lives; this is where what-may-be-done lives,
// and braiding them would give each two homes.

package server

import (
	"context"
	"net"
	"net/http"

	"github.com/zap-proto/zip"
)

// Relay is the address at which a chain accepts a write from anyone: already
// signed transaction bytes, forwarded to consensus. The node checks no
// signature there because it holds no key that could have made one — the bytes
// carry their own authority.
//
// One address, deliberately. An operation that takes signed bytes and is
// registered anywhere else meets [Refused], which is a loud wrong answer rather
// than a quiet open door.
const Relay = "/tx"

// Refused is the stem of every refusal this rule speaks. Exported because a
// test has to tell it from the other 403s an operation can meet — a suite that
// only asked whether something refused would pass with this control deleted.
const Refused = "this changes the node, and a node answers to its operator"

// Authorize is the node's one authorization decision, run at the invoke seam of
// every typed op on every mounted app. [Mount] installs it; nothing else needs
// to, and nothing else should.
func Authorize(ctx context.Context, op zip.Op, _ any) error {
	if Open(op) {
		return nil
	}
	return operator(ctx)
}

// Open reports whether op answers to anyone.
func Open(op zip.Op) bool {
	switch op.Method {
	case http.MethodGet, http.MethodHead:
		return true
	}
	return op.Path == Relay
}

// operator admits the operator of this node and refuses everyone else.
//
// The node already states who that is, in the address it binds: http-host is
// 127.0.0.1 (config/flags.go:249), so a default node serves its API to this
// machine and to nowhere else. Reading the same fact here moves it from the
// process to the operation, which is the whole difference — an operator who
// widens the bind to serve reads to the network stops serving admin to it in
// the same stroke, instead of choosing both at once or neither.
//
// What it reads is the SOCKET PEER, which a caller cannot state about itself:
// zip does not believe X-Forwarded-For unless a deployment names its proxies,
// and this one names none (zip caller.go:314-330).
//
// ONE ADMITTING CLAUSE, because an absence is not a credential. The transport
// reports NO address for a peer it cannot resolve, so a rule that also admitted
// an addressless call would admit an unreadable one, and an unreadable address
// is the input a caller controls least and a hop mangles most.
// TestAnUnreadablePeerIsNotTheOperator holds it to one. Node's own code reaches
// an operation by calling the Go method, in the same process, with no address
// to present and nothing to prove.
func operator(ctx context.Context) error {
	if here(zip.CallerOf(ctx).IP) {
		return nil
	}
	return zip.ErrForbidden(Refused)
}

// here reports whether ip is this machine. An address that does not parse is
// not this machine — an unknown peer is refused, never admitted.
func here(ip string) bool {
	addr := net.ParseIP(ip)
	return addr != nil && addr.IsLoopback()
}
