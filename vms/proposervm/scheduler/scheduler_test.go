// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package scheduler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	core "github.com/luxfi/consensus/core"
	"github.com/luxfi/log"
)

func TestDelayFromNew(t *testing.T) {
	toEngine := make(chan core.Message, 10)
	startTime := time.Now().Add(50 * time.Millisecond)

	s, fromVM := New(log.NoLog{}, toEngine)
	defer s.Close()
	go s.Dispatch(startTime)

	fromVM <- core.Message{Type: core.PendingTxs}

	<-toEngine
	require.LessOrEqual(t, time.Until(startTime), time.Duration(0))
}

func TestDelayFromSetTime(t *testing.T) {
	toEngine := make(chan core.Message, 10)
	now := time.Now()
	startTime := now.Add(50 * time.Millisecond)

	s, fromVM := New(log.NoLog{}, toEngine)
	defer s.Close()
	go s.Dispatch(now)

	s.SetBuildBlockTime(startTime)

	fromVM <- core.Message{Type: core.PendingTxs}

	<-toEngine
	require.LessOrEqual(t, time.Until(startTime), time.Duration(0))
}

func TestReceipt(*testing.T) {
	toEngine := make(chan core.Message, 10)
	now := time.Now()
	startTime := now.Add(50 * time.Millisecond)

	s, fromVM := New(log.NoLog{}, toEngine)
	defer s.Close()
	go s.Dispatch(now)

	fromVM <- core.Message{Type: core.PendingTxs}

	s.SetBuildBlockTime(startTime)

	<-toEngine
}
