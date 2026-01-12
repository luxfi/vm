// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build linux
// +build linux

// ^ SIGTERM signal is not available on Windows
// ^ syscall.SysProcAttr only has field Pdeathsig on Linux

package subprocess

import (
	"context"
	"os/exec"
	"syscall"

	"github.com/luxfi/log"
	"github.com/luxfi/codec/wrappers"
	"github.com/luxfi/vm/rpc/runtime"
)

func NewCmd(path string, args ...string) *exec.Cmd {
	cmd := exec.Command(path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	return cmd
}

func stop(ctx context.Context, log log.Logger, cmd *exec.Cmd) {
	waitChan := make(chan error)
	go func() {
		// attempt graceful shutdown
		errs := wrappers.Errs{}
		err := cmd.Process.Signal(syscall.SIGTERM)
		errs.Add(err)
		_, err = cmd.Process.Wait()
		errs.Add(err)
		waitChan <- errs.Err
		close(waitChan)
	}()

	ctx, cancel := context.WithTimeout(ctx, runtime.DefaultGracefulTimeout)
	defer cancel()

	select {
	case err := <-waitChan:
		if err == nil {
			log.Debug("subprocess gracefully shutdown")
		} else {
			log.Error("subprocess graceful shutdown failed", "error", err)
		}
	case <-ctx.Done():
		// force kill
		err := cmd.Process.Kill()
		log.Error("subprocess was killed", "error", err)
	}
}
