// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package version

import (
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCurrentRPCChainVMCompatible(t *testing.T) {
	compatibleVersions := RPCChainVMProtocolCompatibility[RPCChainVMProtocol]
	// Compared by version, not by require.Contains: that is a deep equal over
	// *Semantic, whose cached str field is populated by the first String() call,
	// so it would pass or fail depending on which test ran first under -shuffle.
	require.True(t, slices.ContainsFunc(
		compatibleVersions,
		func(v *Semantic) bool { return v.Compare(Current) == 0 },
	), "%s missing from RPCChainVMProtocol %d", Current, RPCChainVMProtocol)
}

// TestCurrentMatchesReleaseTag keeps version/version.txt honest.
//
// The version a luxd reports is what the conformance corpus pins other
// implementations against, so it has to be the version that was released. When
// version.txt was not the single source, the tag said 1.36.177 while a plain
// `go build` reported 1.36.35.
//
// A release bumps version.txt and then tags to match; this fails in between.
func TestCurrentMatchesReleaseTag(t *testing.T) {
	out, err := exec.Command("git", "describe", "--tags", "--abbrev=0").Output()
	if err != nil {
		t.Skip("no reachable git tag (shallow clone or archive); nothing to compare against")
	}

	tag, err := Parse(strings.TrimSpace(string(out)))
	require.NoError(t, err)
	require.Zerof(t, tag.Compare(Current),
		"version/version.txt says %s, most recent git tag says %s", Current, tag)
}
