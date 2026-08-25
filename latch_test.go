// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import (
	"context"
	"sync"
	"testing"
	"time"
)

// waitFor runs a latch wait on its own goroutine so a test can tell blocking
// from returning without hanging the suite when it gets it wrong.
func waitFor(l *Latch, ctx context.Context) chan error {
	done := make(chan error, 1)
	go func() {
		_, err := l.WaitForEvent(ctx)
		done <- err
	}()
	return done
}

func TestLatchWakesAWaiter(t *testing.T) {
	var l Latch
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := waitFor(&l, ctx)
	select {
	case err := <-done:
		t.Fatalf("a waiter returned %v before there was any work", err)
	case <-time.After(50 * time.Millisecond):
	}

	l.Signal()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waiting for work: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("work was signalled and the waiter never woke; the chain would never leave genesis")
	}
}

// A signal that arrives before anyone waits still has to be delivered, or work
// submitted between two build attempts is never built.
func TestLatchKeepsASignalNobodyIsWaitingFor(t *testing.T) {
	var l Latch
	l.Signal()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := l.WaitForEvent(ctx); err != nil {
		t.Fatalf("a signal sent before anyone waited was lost: %v", err)
	}
}

// Signalling is idempotent while pending: a builder needs to know there is work,
// not how much. What must not happen is a second wait returning for a signal
// already consumed.
func TestLatchDoesNotWakeTwiceForOneSignal(t *testing.T) {
	var l Latch
	l.Signal()
	l.Signal()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := l.WaitForEvent(ctx); err != nil {
		t.Fatalf("first wait: %v", err)
	}

	brief, cancelBrief := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelBrief()
	if _, err := l.WaitForEvent(brief); err == nil {
		t.Fatal("a second wait returned work for a signal already taken")
	}
}

func TestLatchGivesUpWithItsContext(t *testing.T) {
	var l Latch
	ctx, cancel := context.WithCancel(context.Background())
	done := waitFor(&l, ctx)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled wait reported work")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cancelled wait never returned; a VM could not be shut down")
	}
}

// Signal is called from whatever goroutine accepted the work, which is not the
// one waiting. Run with -race.
func TestLatchSignalsConcurrently(t *testing.T) {
	var l Latch
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Signal()
		}()
	}
	wg.Wait()

	if _, err := l.WaitForEvent(ctx); err != nil {
		t.Fatalf("64 concurrent signals woke nobody: %v", err)
	}
}
