//go:build !grpc

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package subprocess

import (
	"context"
	"io"
	"net"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/vm/rpc/runtime"
)

// TestBootstrapRefusesAnUnsetLog holds the logger guard to surviving the case
// it is named for.
//
// Log is an interface, so an unset one has no dynamic type and IsZero() has
// nothing to call — the guard against a missing logger was the line that
// dereferenced it. The caller (rpc.factory.New) forwards the logger it is
// handed without looking at it, so an unset one arrives here rather than being
// caught upstream, and it arrives as a panic on the config check instead of the
// ErrInvalidConfig this returns for every other missing field.
func TestBootstrapRefusesAnUnsetLog(t *testing.T) {
	require := require.New(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(err)

	// cmd is non-nil so the switch reaches the Log case, and Bootstrap returns
	// before cmd.Start(), so nothing is spawned.
	_, _, err = Bootstrap(
		context.Background(),
		listener,
		exec.Command("true"),
		&Config{Stdout: io.Discard, Stderr: io.Discard},
	)
	require.ErrorIs(err, runtime.ErrInvalidConfig)
}
