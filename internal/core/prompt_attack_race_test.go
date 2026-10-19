//go:build race

package core

// Source: Go stdlib internal/race/race.go (race build selection).
// Only production wall-clock assertions use this; race correctness still runs.
const promptAttackRaceEnabled = true
