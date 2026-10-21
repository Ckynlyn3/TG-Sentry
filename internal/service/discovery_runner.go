package service

import (
	"aegishook/internal/core"
	"aegishook/internal/core/discovery"
	"context"
	"log"
	"time"
)

// Reuse policy_refresh.go's function-variable seams for deterministic tests.
var readServiceDiscoveryBundle = core.ReadDiscoveryBundle
var discoveryNow = time.Now
var runServiceDiscovery = func(ctx context.Context, dir string) (discovery.Report, error) {
	return core.RunDiscovery(ctx, dir, discovery.AllLocalAccounts, nil, nil)
}

// discoveryRunner belongs exclusively to the policy refresh worker. No second
// goroutine/ticker is needed: effective scheduling granularity is the existing
// policyRefreshInterval (60 s, DECISIONS #7), plus refresh/scan execution time.
type discoveryRunner struct {
	revision int
	policy   core.DiscoveryPolicy
	lastScan time.Time
}

func (runner *discoveryRunner) refresh(ctx context.Context, options core.MachineOptions) {
	if ctx.Err() != nil {
		return
	}
	dir := core.MachinePaths(options.Root).Private
	bundle, err := readServiceDiscoveryBundle(dir)
	if err != nil {
		log.Print("machine discovery policy unavailable")
		return
	}
	var policy core.DiscoveryPolicy
	if bundle.Discovery != nil {
		policy = *bundle.Discovery
	}
	changed := bundle.Revision != runner.revision && policy != runner.policy
	if !policy.Enabled || policy.IntervalSeconds <= 0 {
		runner.revision, runner.policy = bundle.Revision, policy
		return
	}
	now := discoveryNow()
	// Compare whole seconds without multiplying the signed policy's int by
	// time.Second: accepted intervals need not fit in a time.Duration.
	if !changed && !runner.lastScan.IsZero() && now.Sub(runner.lastScan)/time.Second < time.Duration(policy.IntervalSeconds) {
		return
	}
	report, err := runServiceDiscovery(ctx, dir)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		runner.revision, runner.policy = bundle.Revision, policy
		runner.lastScan = now                 // Bound failed attempts by the policy interval too.
		log.Print("machine discovery failed") // Never log path/credential-bearing causes.
		return
	}
	if !report.Final {
		// Scan deliberately hides OS causes: contention, enumeration failure and
		// cancellation are all non-final. Retry on the next successful refresh.
		log.Print("machine discovery skipped: scan locked or incomplete")
		return
	}
	runner.revision, runner.policy = bundle.Revision, policy
	runner.lastScan = now
}
