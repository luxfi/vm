// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package version

import (
	"slices"
	"strings"
	"time"

	"github.com/go-json-experiment/json"

	_ "embed"
)

const (
	Client = "luxd"
	// RPCChainVMProtocol should be bumped anytime changes are made which
	// require the plugin vm to upgrade to latest node release to be
	// compatible.
	RPCChainVMProtocol uint = 42
)

// version.txt is the one place this repo states its own version.
//
// It is embedded rather than injected via ldflags so that every way of
// producing a luxd reports the same number: `go run`, a plain `go build`, a
// test binary and scripts/build.sh all read this file. scripts/git_commit.sh
// reads the same file for the build banner and image tags.
//
//go:embed version.txt
var versionBytes []byte

// These are globals that describe network upgrades and node versions
var (
	Current    *Semantic
	CurrentApp *Application

	MinimumCompatibleVersion = &Application{
		Name:  Client,
		Major: 1,
		Minor: 13,
		Patch: 0,
	}
	PrevMinimumCompatibleVersion = &Application{
		Name:  Client,
		Major: 1,
		Minor: 12,
		Patch: 0,
	}

	CurrentDatabase = DatabaseVersion1_4_5
	PrevDatabase    = DatabaseVersion1_0_0

	DatabaseVersion1_4_5 = &Semantic{
		Major: 1,
		Minor: 4,
		Patch: 5,
	}
	DatabaseVersion1_0_0 = &Semantic{
		Major: 1,
		Minor: 0,
		Patch: 0,
	}

	//go:embed compatibility.json
	rpcChainVMProtocolCompatibilityBytes []byte
	// RPCChainVMProtocolCompatibility maps RPCChainVMProtocol versions to the
	// set of node versions that supported that version. This is not used
	// by node, but is useful for downstream libraries.
	RPCChainVMProtocolCompatibility map[uint][]*Semantic
)

func init() {
	major, minor, patch, err := parseVersions(strings.TrimSpace(string(versionBytes)))
	if err != nil {
		panic("invalid version/version.txt: " + err.Error())
	}

	Current = &Semantic{
		Major: major,
		Minor: minor,
		Patch: patch,
	}
	CurrentApp = &Application{
		Name:  Client,
		Major: Current.Major,
		Minor: Current.Minor,
		Patch: Current.Patch,
	}

	// Parse RPC compatibility map
	var parsedRPCChainVMCompatibility map[uint][]string
	if err := json.Unmarshal(rpcChainVMProtocolCompatibilityBytes, &parsedRPCChainVMCompatibility); err != nil {
		panic(err)
	}

	RPCChainVMProtocolCompatibility = make(map[uint][]*Semantic)
	for rpcChainVMProtocol, versionStrings := range parsedRPCChainVMCompatibility {
		versions := make([]*Semantic, len(versionStrings))
		for i, versionString := range versionStrings {
			version, err := Parse(versionString)
			if err != nil {
				panic(err)
			}
			versions[i] = version
		}
		RPCChainVMProtocolCompatibility[rpcChainVMProtocol] = versions
	}

	// This build speaks RPCChainVMProtocol by construction, so it says so itself
	// rather than waiting for someone to remember to append it to
	// compatibility.json on release day. The file is the record of past
	// releases; this is the present one.
	//
	// Nobody remembered for 142 releases: the list stopped at v1.36.35, and the
	// test meant to catch that could not, because Current was hardcoded to
	// v1.36.35 too.
	if !slices.ContainsFunc(
		RPCChainVMProtocolCompatibility[RPCChainVMProtocol],
		func(v *Semantic) bool { return v.Compare(Current) == 0 },
	) {
		RPCChainVMProtocolCompatibility[RPCChainVMProtocol] = append(
			RPCChainVMProtocolCompatibility[RPCChainVMProtocol],
			Current,
		)
	}
}

func GetCompatibility(minCompatibleTime time.Time) Compatibility {
	return NewCompatibility(
		CurrentApp,
		MinimumCompatibleVersion,
		minCompatibleTime,
		PrevMinimumCompatibleVersion,
	)
}
