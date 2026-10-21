package main

import (
	"aegishook/internal/eval"
	"context"
	"errors"
	"fmt"
	"os"
)

func runEval(ctx context.Context, o options) error {
	if o.evalDevOnly {
		return runEvalDev(ctx, o)
	}
	if o.evalManifest == "" || o.evalLock == "" || o.evalConfig == "" || o.evalOut == "" || o.evalSealed == "" {
		return errors.New("eval requires --manifest, --lock, --config, --sealed-dir and --out")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	// #20/#21 integration supplies Detector and independently observed LiveDigests
	// here. Until then nil selects noop: unavailable, never a scored negative.
	report, err := eval.Run(ctx, eval.RunOptions{Root: root, Manifest: o.evalManifest, Lock: o.evalLock, Config: o.evalConfig, SealedDir: o.evalSealed, Out: o.evalOut})
	if err != nil {
		return err
	}
	if len(report.Thresholds) == 0 {
		return errors.New("evaluation has no frozen thresholds; no acceptance verdict")
	}
	scored := 0
	for _, g := range report.Groups {
		scored += g.NScored
	}
	if scored == 0 {
		return errors.New("evaluation has no scored items; detectors may be unavailable")
	}
	for _, t := range report.Thresholds {
		if t.Status == "FAIL" || t.Status == "NOT_MEASURED" {
			return errors.New("evaluation thresholds did not pass; see report")
		}
	}
	return nil
}

func runEvalDev(ctx context.Context, o options) error {
	if o.evalManifest != "" || o.evalLock != "" || o.evalSealed != "" {
		return errors.New("dev-only refuses external dataset paths")
	}
	if o.evalConfig == "" || o.evalOut == "" {
		return errors.New("dev-only eval requires explicit --config and --out")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	report, err := eval.RunDev(ctx, eval.DevOptions{Root: root, Config: o.evalConfig, Out: o.evalOut})
	if err != nil {
		return err
	}
	scored, unavailable := 0, 0
	for _, g := range report.Groups {
		scored += g.NScored
		unavailable += g.NUnavailable
	}
	fmt.Fprintf(os.Stdout, "DEV-ONLY full-path GenerateDev run: %d scored, %d unavailable; no acceptance verdict. Reports: %s\n", scored, unavailable, o.evalOut)
	if scored == 0 || unavailable != 0 {
		return errors.New("dev-only full-path run incomplete; see report")
	}
	return nil
}
