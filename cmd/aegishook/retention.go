package main

import (
	"aegishook/internal/core"
	"context"
	"log/slog"
	"time"
)

// retentionPurgeInterval is the periodic expiry cadence for events and audit
// records. MongoDB's TTL monitor evaluates expired documents every 60 seconds;
// that documented default is the cited precedent, not a tuned value. There is no
// operator knob because no source justifies a different number.
// https://www.mongodb.com/docs/manual/core/index-ttl/#timing-of-the-delete-operation
const retentionPurgeInterval = 60 * time.Second

// Replaceable seams. Production uses the stdlib ticker, the engine clock and the
// reviewed core retention operations; tests substitute a manual tick channel and
// an offset clock so no test waits out the real cadence or retention horizon.
var newRetentionTicker = func(interval time.Duration) (<-chan time.Time, func()) {
	ticker := time.NewTicker(interval)
	return ticker.C, ticker.Stop
}

// retentionNow reads the single engine clock, so each run captures one UTC now.
var retentionNow = func(e *core.Engine) time.Time { return e.Clock() }

// adoptRetentionPolicy loads operator settings and commits them once at startup.
var adoptRetentionPolicy = func(ctx context.Context, e *core.Engine) error {
	p, err := core.LoadRetentionPolicy()
	if err != nil {
		return err
	}
	return e.AdoptRetentionPolicy(ctx, p)
}

var purgeExpired = func(ctx context.Context, e *core.Engine, now time.Time) (core.PurgeResult, error) {
	return e.PurgeExpired(ctx, now)
}

// startRetentionPurge owns one serve-owned worker: it adopts the operator policy
// once, purges immediately, then every retentionPurgeInterval. It is deliberately
// separate from the engine's one-second review-expiry loop so a retention failure
// never suppresses ordinary review expiry. stop cancels and joins the worker, so
// a caller that joins before e.Close() cannot purge against a closed database.
func startRetentionPurge(parent context.Context, e *core.Engine) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticks, stopTicker := newRetentionTicker(retentionPurgeInterval)
		defer stopTicker()
		adopted := false
		run := func() {
			if !adopted {
				if err := adoptRetentionPolicy(ctx, e); err != nil {
					if ctx.Err() == nil {
						slog.ErrorContext(ctx, "retention policy adoption failed")
					}
					return
				}
				adopted = true
			}
			if _, err := purgeExpired(ctx, e, retentionNow(e)); err != nil && ctx.Err() == nil {
				// Sanitized operational log: no SQL error text, no content, no
				// credentials. Both failures retry next tick, never a hot loop.
				slog.ErrorContext(ctx, "retention purge failed")
			}
		}
		for ctx.Err() == nil {
			run()
			select {
			case <-ctx.Done():
				return
			case <-ticks:
			}
		}
	}()
	return func() { cancel(); <-done }
}
