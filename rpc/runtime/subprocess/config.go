// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package subprocess

import (
	"io"
	"time"

	"github.com/luxfi/log"
)

// Config contains subprocess configuration.
type Config struct {
	// Stderr of the VM process written to this writer.
	Stderr io.Writer
	// Stdout of the VM process written to this writer.
	Stdout io.Writer
	// Duration engine server will wait for handshake success.
	HandshakeTimeout time.Duration
	Log              log.Logger
}

// Status contains subprocess status after successful bootstrap.
type Status struct {
	// Id of the process.
	Pid int
	// Address of the VM service.
	Addr string
}
