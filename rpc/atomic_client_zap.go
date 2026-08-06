//go:build !grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"fmt"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

// atomic_client_zap.go holds the two pieces of the plugin's Runtime that the
// InitializeRequest cannot carry as scalars.
//
// The shared-memory handle itself lives in vm/chains/atomic/atomiczap, beside
// the interface it transports, so the client and the node's server are one
// package and their round trip is pinned by a test against a real atomic.Memory.
// What remains here is the chain-alias lookup, which does not need a transport
// at all.

// optionalID decodes a fixed-width id that is ALLOWED to be absent on the wire.
//
// ids.ToID rejects any length that is not exactly the ID size, which is what the
// required identifiers (chainID, cChainID, ...) want: a short field there means
// a corrupt handshake, and silently zero-padding it would yield a DIFFERENT
// chain. An optional identifier is different — an empty field is a legitimate
// "this network has no such chain" and must decode to ids.Empty rather than fail
// Initialize. Anything non-empty but mis-sized is still an error, so a truncated
// id can never be mistaken for a valid one.
func optionalID(name string, raw []byte) (ids.ID, error) {
	if len(raw) == 0 {
		return ids.Empty, nil
	}
	id, err := ids.ToID(raw)
	if err != nil {
		return ids.Empty, fmt.Errorf("initialize %s: %w", name, err)
	}
	return id, nil
}

// staticBCLookup resolves the handful of chain aliases a plugin actually needs,
// from ids carried on the Initialize wire.
//
// WHY NOT PROXY THE REAL LOOKUP. runtime.BCLookup is an interface onto the
// node's chain manager. Proxying it would put a synchronous node round trip on
// whatever path called it, and the DEX seam resolves exactly one alias — "D" —
// to a value that is fixed for the life of the network. Carrying the resolved id
// is strictly smaller and cannot fail at an inconvenient moment.
//
// An alias with no id resolves to database.ErrNotFound, the same error the
// node's lookup returns for an unknown alias, so callers that already read that
// as "this network has no such chain" are unchanged. In particular the DEX seam
// reads a missing "D" as "no dexvm deployed" and keeps the on-ramp closed.
type staticBCLookup struct {
	byAlias map[string]ids.ID
}

func newStaticBCLookup(cChainID, xChainID, dChainID ids.ID) *staticBCLookup {
	l := &staticBCLookup{byAlias: make(map[string]ids.ID, 8)}
	set := func(id ids.ID, aliases ...string) {
		if id == ids.Empty {
			return
		}
		for _, a := range aliases {
			l.byAlias[a] = id
		}
	}
	set(cChainID, "C", "evm")
	set(xChainID, "X", "xvm")
	set(dChainID, "D", "dex", "dexvm")
	return l
}

func (l *staticBCLookup) Lookup(alias string) (ids.ID, error) {
	if id, ok := l.byAlias[alias]; ok {
		return id, nil
	}
	return ids.Empty, database.ErrNotFound
}

func (l *staticBCLookup) PrimaryAlias(id ids.ID) (string, error) {
	// The primary alias is the single-letter form — the first registered for
	// each id above.
	for _, alias := range []string{"C", "X", "D"} {
		if got, ok := l.byAlias[alias]; ok && got == id {
			return alias, nil
		}
	}
	return "", database.ErrNotFound
}

func (l *staticBCLookup) Aliases(id ids.ID) ([]string, error) {
	var out []string
	for _, alias := range []string{"C", "evm", "X", "xvm", "D", "dex", "dexvm"} {
		if got, ok := l.byAlias[alias]; ok && got == id {
			out = append(out, alias)
		}
	}
	if len(out) == 0 {
		return nil, database.ErrNotFound
	}
	return out, nil
}
