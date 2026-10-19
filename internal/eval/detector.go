package eval

import (
	"aegishook/internal/core"
	"context"
	"errors"
)

type Input struct {
	Text     string `json:"-"`
	Language string `json:"language"`
	Surface  string `json:"surface"` // prompt | tool_result | file, plan §5.
	Tenant   string `json:"tenant"`
}
type Finding struct {
	Category string `json:"category"`
	Tag      string `json:"tag"`
	Span
	Type  string  `json:"type,omitempty"`
	Score float64 `json:"score"`
}
type Result struct {
	Findings    []Finding `json:"findings"`
	Decision    string    `json:"decision"`
	Unavailable bool      `json:"unavailable"`
	Reason      string    `json:"reason,omitempty"`
}
type Detector interface {
	Detect(context.Context, Input) (Result, error)
}

// Never manufacture a negative before #20/#21 integration.
type noopDetector struct{}

func (noopDetector) Detect(context.Context, Input) (Result, error) {
	return Result{Unavailable: true, Reason: "detector_not_integrated"}, nil
}

type Item struct {
	ID       string            `json:"item_id"`
	Positive bool              `json:"label"`
	Input    Input             `json:"-"`
	Gold     []Entity          `json:"-"`
	Review   *core.ReviewInput `json:"-"`
	Variant  string            `json:"variant,omitempty"`
	Seed     string            `json:"-"`
}

// Provider strings are untrusted on failure paths too. Preserve only the
// decision vocabulary; unavailable responses may instead have no decision.
func outputDecision(decision string, unavailable bool) (string, error) {
	switch decision {
	case "approve", "allow", "reject", "block", "alert", "monitor", "log-only":
		return decision, nil
	default:
		if unavailable {
			return "", nil
		}
		return "", errors.New("invalid detector decision")
	}
}
