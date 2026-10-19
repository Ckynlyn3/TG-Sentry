package eval

import (
	"aegishook/internal/core"
	"context"
)

// PromptAttackDetector is the field-for-field issue #21 detector adapter. The
// eval runner's default detector and dataset composition remain #26-owned.
type PromptAttackDetector struct{ Core core.PromptAttackDetector }

func (d PromptAttackDetector) Detect(ctx context.Context, in Input) (Result, error) {
	result, err := d.Core.Detect(ctx, core.PromptAttackInput{Text: in.Text, Language: in.Language, Surface: in.Surface, Tenant: in.Tenant})
	out := Result{Findings: make([]Finding, 0, len(result.Findings)), Decision: result.Decision, Unavailable: result.Unavailable, Reason: result.Reason}
	for _, f := range result.Findings {
		out.Findings = append(out.Findings, Finding{Category: f.Category, Tag: f.Tag, Span: Span{StartUTF16: f.StartUTF16, EndUTF16: f.EndUTF16}, Type: f.Type, Score: f.Score})
	}
	return out, err
}
