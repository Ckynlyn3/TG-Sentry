package service

import (
	"aegishook/internal/core"
	"context"
	"log"
	"time"
)

// DECISIONS #7 / ARCHITECTURE §2.3: Alibaba plugin 1.4.2's 60 s ETag polling.
const policyRefreshInterval = 60 * time.Second

// Keep the stdlib ticker and existing machine verifier replaceable in tests.
var newPolicyRefreshTicker = func(interval time.Duration) (<-chan time.Time, func()) {
	ticker := time.NewTicker(interval)
	return ticker.C, ticker.Stop
}
var refreshMachinePolicy = core.MachineEnrolledContext

// startPolicyRefresh owns one worker; stop cancels and joins it even on serve failure.
func startPolicyRefresh(parent context.Context, options core.MachineOptions) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticks, stopTicker := newPolicyRefreshTicker(policyRefreshInterval)
		defer stopTicker()
		var discovery discoveryRunner
		for ctx.Err() == nil {
			if err := refreshMachinePolicy(ctx, options); err != nil {
				if ctx.Err() == nil {
					log.Printf("machine policy refresh failed: %v", err)
				}
			} else {
				discovery.refresh(ctx, options)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticks:
			}
		}
	}()
	return func() { cancel(); <-done }
}
