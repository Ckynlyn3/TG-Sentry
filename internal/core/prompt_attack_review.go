package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

// PromptAttackDetector reuses the three shipped sources; it never authorizes a
// tool. NSFA is injectable for isolated eval fixtures, not a second transport.
type PromptAttackDetector struct {
	Settings Settings
	Rules    []Rule
	Tool     string // Original tool identity for scoped observational rules.
	NSFA     *NSFAClient
}

func promptAttackSelected(rules []Rule, tool string) []Rule {
	selected := []Rule{}
	for _, r := range rules {
		if r.Enabled && r.Matcher == "prompt-attack" && (r.Tool == "" || r.Tool == tool) {
			selected = append(selected, r)
		}
	}
	sortRules(selected)
	return selected
}
func attributePromptAttack(source PromptAttackResult, rules []Rule) PromptAttackResult {
	out := source
	out.Findings = []PromptAttackFinding{}
	for _, finding := range source.Findings {
		for _, r := range rules {
			if r.Pattern == finding.Tag {
				f := finding
				f.RuleID = r.ID
				f.SourceRuleID = r.SourceRuleID
				if f.SourceRuleID == "" {
					f.SourceRuleID = r.ID
				}
				out.Findings = append(out.Findings, f)
			}
		}
	}
	return out
}
func promptAttackUndecided(rules []Rule, result PromptAttackResult) bool {
	for _, r := range rules {
		found := false
		for _, f := range result.Findings {
			if f.RuleID == r.ID && f.Type == "pattern" {
				found = true
			}
		}
		if !found {
			return true
		}
	}
	return false
}
func appendPromptAttack(a, b PromptAttackResult) PromptAttackResult {
	a.Findings = append(a.Findings, b.Findings...)
	a.Evidence = append(a.Evidence, b.Evidence...)
	if b.Unavailable {
		a.Unavailable = true
		if a.Reason != "" {
			a.Reason += ";"
		}
		a.Reason += b.Reason
	}
	return a
}
func mergePromptAttack(current *Decision, result PromptAttackResult, rules []Rule, monitor bool) *Decision {
	// XACML deny-overrides: an existing denial is immutable.
	if current != nil && current.Decision == "reject" {
		return current
	}
	for _, f := range result.Findings {
		if monitor && strings.HasPrefix(f.Type, "nsfa:") {
			continue
		}
		for _, r := range rules {
			if r.ID == f.RuleID && (current == nil || decisionStrength(r.Decision) > decisionStrength(current.Decision)) {
				current = &Decision{Decision: r.Decision, RuleID: r.ID, Comment: "Prompt-attack detection; rule " + eventIdentifier(r.ID)}
			}
		}
	}
	return current
}
func promptAttackFailure(current *Decision, result PromptAttackResult, rules []Rule, nsfaMode string) *Decision {
	if !result.Unavailable || current != nil && current.Decision == "reject" {
		return current
	}
	for _, r := range rules {
		if r.Decision == "reject" {
			classifierFailure := strings.Contains(result.Reason, "classifier_")
			if classifierFailure || nsfaMode == "enforce" {
				id := "E_MODEL"
				if !classifierFailure {
					id = "E_NSFA"
				}
				return &Decision{Decision: "reject", RuleID: id, Comment: "Prompt-attack detector unavailable; request denied."}
			}
		}
	}
	return current
}
func (d PromptAttackDetector) Detect(ctx context.Context, in PromptAttackInput) (PromptAttackResult, error) {
	if !utf8.ValidString(in.Text) || in.Tenant != "" && in.Tenant != eventTenant() || !hasExact(in.Surface, "prompt", "tool_input", "tool_result", "file") {
		return PromptAttackResult{Unavailable: true, Reason: "invalid_input"}, errors.New("invalid prompt-attack input")
	}
	rules := promptAttackSelected(d.Rules, d.Tool)
	result := attributePromptAttack(scanPromptAttackPatterns(in), rules)
	result = d.detectRemaining(ctx, in, rules, result)
	decision := mergePromptAttack(nil, result, rules, d.Settings.NSFA.Mode != "enforce")
	if in.Surface != "tool_result" && in.Surface != "file" {
		decision = promptAttackFailure(decision, result, rules, d.Settings.NSFA.Mode)
	} else {
		decision = nil
	}
	result.Decision = "approve"
	if decision != nil {
		result.Decision = decision.Decision
	}
	return result, nil
}
func (d PromptAttackDetector) detectRemaining(ctx context.Context, in PromptAttackInput, rules []Rule, result PromptAttackResult) PromptAttackResult {
	type detected struct {
		source string
		result PromptAttackResult
	}
	pending := map[string]bool{}
	done := make(chan detected, 2) // One classifier and one NSFA task.
	if promptAttackUndecided(rules, result) {
		pending["classifier"] = true
		go func() {
			s := d.Settings
			if s.PromptAttack.Model != nil {
				s.Model = *s.PromptAttack.Model
			}
			done <- detected{"classifier", classifyPromptAttack(ctx, s, in, promptAttackIndicatorNames(in))}
		}()
	}
	if d.Settings.NSFA.Mode != "" && d.Settings.NSFA.Mode != "off" && len(rules) > 0 {
		pending["nsfa"] = true
		go func() {
			client := d.NSFA
			if client == nil {
				client = loadPromptAttackNSFA(d.Settings.NSFA)
			}
			bounded, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer cancel()
			task := "query"
			// Output surfaces use the opt-in hazardous-generation response head;
			// prompt/tool arguments remain queries. Reuse the same remaining budget.
			if d.Settings.NSFA.ResponseHead && hasExact(in.Surface, "tool_result", "file") {
				task = "response"
			}
			done <- detected{"nsfa", client.Classify(bounded, in.Text, task, "")}
		}()
	}
	merge := func(got detected) {
		delete(pending, got.source)
		result = appendPromptAttack(result, attributePromptAttack(got.result, rules))
	}
	for len(pending) > 0 {
		select {
		case got := <-done:
			merge(got)
		case <-ctx.Done():
			// select may choose cancellation while completed results are queued.
			// Keep those findings and mark only sources still outstanding.
			for len(done) > 0 { // This goroutine is the only receiver.
				merge(<-done)
			}
			for _, source := range []string{"classifier", "nsfa"} {
				if pending[source] {
					reason := source + "_timeout"
					if ctx.Err() == context.Canceled {
						reason = source + "_canceled"
					}
					result = appendPromptAttack(result, PromptAttackResult{Unavailable: true, Reason: reason})
				}
			}
			return result
		}
	}
	return result
}
func promptAttackIndicatorNames(in PromptAttackInput) []string {
	out := []string{}
	for _, e := range scanPromptAttackPatterns(in).Evidence {
		out = append(out, e.Type)
	}
	return out
}

func reviewPromptAttack(in PromptAttackInput, rules []Rule, current *Decision) (*Decision, *PromptAttackResult, bool) {
	if len(rules) == 0 {
		return current, nil, false
	}
	if current != nil && current.Decision == "reject" {
		return current, &PromptAttackResult{Decision: "reject", Reason: "deterministic denial; prompt-attack scan skipped"}, false
	}
	result := attributePromptAttack(scanPromptAttackPatterns(in), rules)
	current = mergePromptAttack(current, result, rules, false)
	result.Decision = "approve"
	if current != nil {
		result.Decision = current.Decision
	}
	return current, &result, promptAttackUndecided(rules, result)
}
func promptAttackOriginal(in ReviewInput) PromptAttackInput {
	if in.ToolName == "prompt_turn" {
		return PromptAttackInput{Text: in.UserMessage, Surface: "prompt", Tenant: eventTenant()}
	}
	b, _ := json.Marshal(struct {
		Tool            string
		Args            map[string]any
		Prompt, Context string
		Scripts         []ReviewScript
	}{in.ToolName, in.Arguments, in.UserMessage, in.Context, in.Scripts})
	return PromptAttackInput{Text: string(b), Surface: "tool_input", Tenant: eventTenant()}
}

// The authorization baseline stays goroutine-local, alongside the original input.
// Human lifetimes are independent of the detector deadline (plan H3).
func (e *Engine) promptAttackReview(ctx context.Context, cancel context.CancelFunc, r Review, s Settings, original PromptAttackInput, rules []Rule, baseline *Decision, human bool, nsfa *NSFAClient) {
	defer cancel()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-e.stop:
			cancel()
		case <-finished:
		}
	}()
	type judged struct {
		d     Decision
		err   error
		usage *TokenUsage
	}
	judge := make(chan judged, 1)
	needsJudge := baseline == nil && !human && original.Surface != "prompt"
	if needsJudge {
		go func() {
			bounded, stop := context.WithTimeout(ctx, time.Duration(s.ModelSeconds)*time.Second)
			defer stop()
			var usage *TokenUsage
			d, err := callModelWithUsage(bounded, s, modelInput(r), &usage)
			judge <- judged{d, err, usage}
		}()
	}
	result := PromptAttackResult{}
	if r.PromptAttack != nil {
		result = *r.PromptAttack
		result.Reason = ""
		result = (PromptAttackDetector{Settings: s, Rules: rules, NSFA: nsfa}).detectRemaining(ctx, original, rules, result)
	}
	decision := mergePromptAttack(baseline, result, rules, s.NSFA.Mode != "enforce")
	decision = promptAttackFailure(decision, result, rules, s.NSFA.Mode)
	if original.Surface != "prompt" && (decision == nil || decision.Decision != "reject") {
		decision = baseline
	}
	var verdict *Decision
	var usage *TokenUsage
	judgeFailed := false
	if needsJudge {
		var got judged
		select {
		case got = <-judge:
		case <-ctx.Done():
			// A completed judge remains authoritative when monitor-only detection
			// consumes the remaining budget. Never replace a queued verdict.
			select {
			case got = <-judge:
			default:
				got.err = ctx.Err()
			}
		}
		usage = got.usage
		judgeFailed = got.err != nil
		if got.err != nil {
			got.d = Decision{Decision: "reject", RuleID: "E_MODEL", Comment: "Tool judge unavailable; request denied."}
		}
		verdict = &got.d
		if decision == nil || decision.Decision != "reject" && got.d.Decision == "reject" {
			decision = &got.d
		}
	}
	if original.Surface == "prompt" && decision == nil {
		decision = &Decision{Decision: "approve", RuleID: "PA_CLEAN", Comment: "Prompt-attack check completed."}
	}
	if human && original.Surface != "prompt" && (decision == nil || decision.Decision != "reject") {
		decision = nil
	}
	// Audit writes may outlive the endpoint deadline; they cannot emit a late permit.
	audit := WithActor(context.Background(), SystemActor("model-review"))
	e.mu.Lock()
	defer e.mu.Unlock()
	if needsJudge {
		if err := e.recordUsage(r.ID, r.ID, "review", s, usage, judgeFailed); err != nil {
			return
		}
	}
	current, err := e.Review(r.ID)
	if err != nil || current.Decision != "pending" {
		return
	}
	if r.PromptAttack != nil {
		result.Decision = "approve"
		if decision != nil {
			result.Decision = decision.Decision
		}
		current.PromptAttack = &result
	}
	current.ModelVerdict = verdict
	if verdict != nil && verdict.Decision == "approve" && current.ScriptCaptureStatus == "incomplete" && (decision == nil || decision.Decision != "reject") {
		decision = nil
	}
	if decision == nil {
		current.NeedsHuman = true
		current.ReviewPath = "human"
		e.commitReview(audit, current, "review.model")
		return
	}
	current.Decision = decision.Decision
	if current.Decision == "alert" {
		current.Decision = "approve"
	}
	current.RuleID = decision.RuleID
	current.Comment = decision.Comment
	if strings.HasPrefix(current.RuleID, "R_PA_") || hasPromptAttackFinding(result, current.RuleID) {
		current.ReviewPath = "rule"
	} else if verdict != nil {
		current.ReviewPath = "model"
	}
	current.NeedsHuman = false
	now := e.clock()
	current.DecidedAt = &now
	if current.Decision == "approve" {
		current.Execution = "awaiting_execution"
	}
	e.commitReview(audit, current, "review.model")
}
func hasPromptAttackFinding(result PromptAttackResult, id string) bool {
	for _, f := range result.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// Named local exception: X-TG-Expected-Rq-Timeout-Ms mirrors Envoy's remaining
// millisecond request timeout, capped by the existing review-hook-budget.
func ReviewRequestBudget(value string) time.Duration {
	var ms int64
	if json.Unmarshal([]byte(value), &ms) != nil || ms <= 0 {
		return ReviewHookBudget
	}
	if ms > ReviewHookBudget.Milliseconds() {
		return ReviewHookBudget
	}
	return time.Duration(ms) * time.Millisecond
}

// Bound response time even when the engine mutex/audit store is busy. The
// worker owns the immutable verdict and may finish its audit after this returns.
func (e *Engine) SubmitContext(parent context.Context, in ReviewInput) (Review, error) {
	deadline := time.Now().Add(ReviewHookBudget)
	if d, ok := parent.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	ctx, cancel := context.WithDeadline(context.WithoutCancel(parent), deadline)
	type outcome struct {
		r   Review
		err error
	}
	done := make(chan outcome, 1)
	go func() { r, err := e.submit(ctx, cancel, in); done <- outcome{r, err} }()
	select {
	case got := <-done:
		if got.err != nil || got.r.Decision != "pending" || got.r.ReviewPath == "human" {
			cancel()
		}
		return got.r, got.err
	case <-parent.Done():
		cancel()
		return Review{Decision: "reject", Execution: "not_executed", RuleID: "E_TIMEOUT"}, parent.Err()
	case <-ctx.Done():
		cancel()
		return Review{Decision: "reject", Execution: "not_executed", RuleID: "E_TIMEOUT"}, ctx.Err()
	}
}

// Reuse #20's bounded plain-token file shape; only fixture files are used by tests.
func promptAttackFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("sidecar configuration unavailable")
	}
	defer f.Close()
	if stat, err := f.Stat(); err != nil || !stat.Mode().IsRegular() {
		return nil, errors.New("sidecar configuration unavailable")
	}
	b, err := io.ReadAll(io.LimitReader(f, btpiiResponseBytes+1))
	if err != nil || len(b) > btpiiResponseBytes {
		return nil, errors.New("sidecar configuration unavailable")
	}
	return b, nil
}
func loadPromptAttackNSFA(cfg NSFAConfig) *NSFAClient {
	path := cfg.TokenFile
	if path == "" {
		path = os.Getenv("TG_NSFA_WORKLOAD_TOKEN_FILE")
	}
	token, _ := promptAttackFile(path)
	identityBytes, _ := promptAttackFile(cfg.IdentityFile)
	var identity NSFAIdentity
	json.Unmarshal(identityBytes, &identity)
	return NewNSFAClient(cfg, NSFAAuth{Token: strings.TrimSpace(string(token)), WorkloadIdentity: os.Getenv("TG_NSFA_WORKLOAD_ID"), WorkloadCredential: os.Getenv("TG_NSFA_WORKLOAD_CREDENTIAL_ID")}, identity)
}

type nsfaAvailability struct {
	Gate         string `json:"gate"`
	Result       string `json:"result"`
	ConfigSHA256 string `json:"configSHA256"`
	Identity     struct {
		ManifestSHA256 string            `json:"manifest_sha256"`
		Heads          map[string]string `json:"heads"`
	} `json:"identity"`
	Lambda        float64   `json:"lambda"`
	N             int       `json:"n"`
	WilsonUpper95 float64   `json:"wilsonUpper95"`
	RecordedAt    time.Time `json:"recordedAt"`
}

// configSHA256 verifies the operator declaration, not the runtime file bytes.
// Named local exception: issue21-nsfa-frozen-declaration; byte binding is #26.
func (e *Engine) nsfaEnforceAvailable(cfg NSFAConfig) bool {
	var record nsfaAvailability
	if e.get("nsfa_availability", "current", &record) != nil || record.Gate != "NSFA-AVAIL-0" || record.Result != "PASS" || !nsfaHash.MatchString(cfg.FrozenConfigSHA256) || record.ConfigSHA256 != cfg.FrozenConfigSHA256 || cfg.DeclaredLambda <= 0 || math.IsNaN(cfg.DeclaredLambda) || math.IsInf(cfg.DeclaredLambda, 0) || record.Lambda != cfg.DeclaredLambda || record.N <= 0 || record.RecordedAt.IsZero() || !(record.WilsonUpper95 >= 0 && record.WilsonUpper95 <= 1) {
		return false
	}
	b, err := promptAttackFile(cfg.IdentityFile)
	if err != nil {
		return false
	}
	var identity NSFAIdentity
	if json.Unmarshal(b, &identity) != nil || !nsfaValidIdentity(identity) || identity.ManifestSHA256 != record.Identity.ManifestSHA256 {
		return false
	}
	heads := map[string]string{}
	for name, head := range identity.Heads {
		heads[name] = head.SHA256
	}
	return reflect.DeepEqual(heads, record.Identity.Heads)
}

// Exposed for frozen eval adapter identity without duplicating the prompt bytes.
func PromptAttackPromptSHA256() string {
	sum := sha256.Sum256([]byte(promptAttackClassifierPrompt))
	return hex.EncodeToString(sum[:])
}

// Called under the engine mutex. Reuse the S3 client's breaker across reviews;
// refreshing config, expected identity or auth creates a distinct client.
func (e *Engine) promptAttackNSFA(cfg NSFAConfig) *NSFAClient {
	if !hasExact(cfg.Mode, "monitor", "enforce") {
		return nil
	}
	candidate := loadPromptAttackNSFA(cfg)
	if e.paNSFA == nil || !reflect.DeepEqual(e.paNSFA.config, candidate.config) || !reflect.DeepEqual(e.paNSFA.expected, candidate.expected) || e.paNSFA.auth != candidate.auth {
		e.paNSFA = candidate
	}
	return e.paNSFA
}

func nsfaConfigChanged(before, after NSFAConfig) bool {
	before.Mode, after.Mode = "", ""
	before.FrozenConfigSHA256, after.FrozenConfigSHA256 = "", ""
	return before != after
}
