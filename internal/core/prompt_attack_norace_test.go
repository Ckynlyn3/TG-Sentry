//go:build !race

package core

// Source: Go stdlib internal/race/norace.go (non-race build selection).
const promptAttackRaceEnabled = false
