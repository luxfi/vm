// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package subprocess

import (
	"context"
	"os/exec"
	"sync"

	"github.com/luxfi/log"
	"github.com/luxfi/vm/rpc/runtime"
)

func NewStopper(logger log.Logger, cmd *exec.Cmd) runtime.Stopper {
	return &stopper{
		cmd:    cmd,
		logger: logger,
	}
}

type stopper struct {
	once   sync.Once
	cmd    *exec.Cmd
	logger log.Logger
}

func (s *stopper) Stop(ctx context.Context) {
	s.once.Do(func() {
		stop(ctx, s.logger, s.cmd)
	})
}
