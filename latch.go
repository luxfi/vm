// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import (
	"context"
	"sync"
)

// A Latch is how a VM tells consensus there is work to build a block from.
//
// Consensus calls WaitForEvent and builds nothing until it returns. A VM that
// waits only on the context therefore never builds, and its chain never leaves
// genesis however much work it has accepted — the work is there, the news of it
// is not.
//
// Signalling twice before the signal is taken is the same as signalling once:
// what a builder needs to know is that there is work, not how much. The zero
// value is ready to use.
type Latch struct {
	once sync.Once
	c    chan struct{}
}

func (l *Latch) ch() chan struct{} {
	l.once.Do(func() { l.c = make(chan struct{}, 1) })
	return l.c
}

// Signal reports that there is work. It never blocks, so it is safe to call
// while holding a lock — though callers should prefer to release first, since
// the point is to let a builder run.
func (l *Latch) Signal() {
	select {
	case l.ch() <- struct{}{}:
	default:
	}
}

// WaitForEvent blocks until there is work or the context ends, which is exactly
// what the ChainVM method of the same name owes consensus. A VM delegates to it.
func (l *Latch) WaitForEvent(ctx context.Context) (Message, error) {
	select {
	case <-ctx.Done():
		return Message{}, ctx.Err()
	case <-l.ch():
		return Message{Type: PendingTxs}, nil
	}
}
