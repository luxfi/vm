// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package scheduler

import (
	"time"

	core "github.com/luxfi/consensus/core"
	"github.com/luxfi/log"
)

// AutominingScheduler is a scheduler that continuously produces blocks at a fixed interval
type AutominingScheduler interface {
	Scheduler

	// StartAutomining starts continuous block production
	StartAutomining(interval time.Duration)
	// StopAutomining stops continuous block production
	StopAutomining()
}

type autominingScheduler struct {
	*scheduler

	// Channel to control automining
	autominingControl chan autominingCommand
	// Whether automining is currently active
	autominingActive bool
	// Interval between automatic block productions
	autominingInterval time.Duration
}

type autominingCommand struct {
	start    bool
	interval time.Duration
}

// NewAutomining creates a new scheduler with automining capabilities
func NewAutomining(log log.Logger, toEngine chan<- core.Message) (AutominingScheduler, chan<- core.Message) {
	vmToEngine := make(chan core.Message, cap(toEngine))
	baseScheduler := &scheduler{
		log:               log,
		fromVM:            vmToEngine,
		toEngine:          toEngine,
		newBuildBlockTime: make(chan time.Time),
	}

	return &autominingScheduler{
		scheduler:         baseScheduler,
		autominingControl: make(chan autominingCommand, 1),
	}, vmToEngine
}

func (s *autominingScheduler) Dispatch(buildBlockTime time.Time) {
	timer := time.NewTimer(time.Until(buildBlockTime))
	defer timer.Stop()

	// Automining ticker - initially stopped
	autominingTicker := time.NewTicker(time.Hour)
	autominingTicker.Stop()
	defer autominingTicker.Stop()

	for {
		select {
		case <-timer.C: // It's time to tell the engine to try to build a block
			s.handleBuildRequest()

			// If automining is active, reset the timer for the next block
			if s.autominingActive {
				timer.Reset(s.autominingInterval)
			}

		case <-autominingTicker.C: // Automining interval elapsed
			s.handleBuildRequest()

		case cmd := <-s.autominingControl:
			if cmd.start {
				s.log.Info("starting automining",
					log.Duration("interval", cmd.interval),
				)
				s.autominingActive = true
				s.autominingInterval = cmd.interval

				// Stop the regular timer and start automining ticker
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}

				autominingTicker.Reset(cmd.interval)
			} else {
				s.log.Info("stopping automining")
				s.autominingActive = false
				autominingTicker.Stop()

				// Reset the regular timer
				timer.Reset(time.Until(buildBlockTime))
			}

		case buildBlockTime, ok := <-s.newBuildBlockTime:
			// Stop the timer and clear [timer.C] if needed
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}

			if !ok {
				// s.Close() was called
				return
			}

			// Only update the timer if automining is not active
			if !s.autominingActive {
				timer.Reset(time.Until(buildBlockTime))
			}

		case msg := <-s.fromVM:
			// Forward the message from VM to engine
			select {
			case s.toEngine <- msg:
			default:
				// If the channel to the engine is full, drop the message
				s.log.Debug("dropping message from VM",
					log.String("reason", "channel to engine is full"),
					log.Reflect("message", msg),
				)
			}
		}
	}
}

func (s *autominingScheduler) handleBuildRequest() {
	// Send a build block message to the engine
	msg := core.Message{Type: core.PendingTxs}
	select {
	case s.toEngine <- msg:
		s.log.Debug("sent build block request to engine",
			log.Bool("automining", s.autominingActive),
		)
	default:
		s.log.Debug("dropping build block request",
			log.String("reason", "channel to engine is full"),
		)
	}
}

func (s *autominingScheduler) StartAutomining(interval time.Duration) {
	select {
	case s.autominingControl <- autominingCommand{start: true, interval: interval}:
	default:
		s.log.Warn("automining control channel full, command dropped")
	}
}

func (s *autominingScheduler) StopAutomining() {
	select {
	case s.autominingControl <- autominingCommand{start: false}:
	default:
		s.log.Warn("automining control channel full, command dropped")
	}
}

func (s *autominingScheduler) Close() {
	s.scheduler.Close()
	close(s.autominingControl)
}
