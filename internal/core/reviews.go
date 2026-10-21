package core

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"aegishook/internal/secrets"
)

func (e *Engine) Register(i Instance) error {
	ctx := WithActor(context.Background(), SystemActor("hook"))
	e.mu.Lock()
	defer e.mu.Unlock()
	// Caller IDs cannot occupy the server-generated correlation namespace (#10).
	if strings.HasPrefix(i.ID, "sha256:") {
		return errors.New("reserved instance identifier namespace")
	}
	i.ID = screenedIdentifier(i.ID)
	i.SessionID = eventIdentifier(i.SessionID)
	if i.NodeID == "" {
		if real, err := filepath.EvalSymlinks(i.Cwd); err == nil {
			i.Cwd = real
		}
	}
	if i.NodeID != "" {
		id, err := hex.DecodeString(i.NodeID)
		if err != nil || len(id) != 16 || !hasExact(i.Platform, "linux", "darwin", "windows") || !agentPathAbs(i.Cwd, i.Platform) {
			return errors.New("远程节点身份、平台或项目路径无效")
		}
		i.Installations = nil
	}
	i.Agent = AgentID(i.Agent)
	if AgentName(i.Agent) == "" {
		return errors.New("未知 Agent")
	}
	if i.ID == "" || i.SessionID == "" || (i.NodeID == "" && !filepath.IsAbs(i.Cwd)) || i.HookVersion != Version {
		return errors.New("会话字段或 Hook 版本无效")
	}
	// Keep historical validation separate from bindings for this registration.
	// Ignore caller-supplied history; only successful registrations establish it.
	i.ObservedInstallations = nil
	var prev Instance
	if e.get("instances", i.ID, &prev) == nil {
		if prev.SessionID != i.SessionID || prev.Cwd != i.Cwd || AgentID(prev.Agent) != i.Agent || prev.NodeID != i.NodeID || (i.NodeID != "" && prev.Platform != i.Platform) {
			return errors.New("实例身份冲突")
		}
		bindings := i.Installations
		i = prev
		for _, id := range prev.Installations {
			if !hasExact(id, i.ObservedInstallations...) {
				i.ObservedInstallations = append(i.ObservedInstallations, id)
			}
		}
		i.Installations = bindings
	}
	for _, id := range i.Installations {
		if !hasExact(id, i.ObservedInstallations...) {
			i.ObservedInstallations = append(i.ObservedInstallations, id)
		}
	}
	i.StartedAt = e.clock()
	i.Heartbeat = e.clock()
	i.State = "idle"
	i.DisconnectReason = ""
	i.Online = true
	// Admission snapshot, like Review. A retry within a live session keeps the
	// original provenance; a genuinely new registration (no prior record, or a
	// record closed by disconnect) re-evaluates configuration.
	i.LogSuppression = prev.LogSuppression
	if prev.ID == "" || prev.State == "disconnected" {
		protection, err := e.Protection()
		if err != nil {
			return err
		}
		i.LogSuppression = logSuppression(protection, i.NodeID)
	}
	return e.change(ctx, "instances", i.ID, i, "instance.register", AgentName(i.Agent)+" 会话事件已接入")
}
func (e *Engine) Heartbeat(id, state string) error {
	id = screenedIdentifier(id)
	e.mu.Lock()
	defer e.mu.Unlock()
	var i Instance
	if err := e.get("instances", id, &i); err != nil {
		return err
	}
	if i.State == "disconnected" {
		return errors.New("实例已注销，请重新注册")
	}
	i.Heartbeat = e.clock()
	if hasExact(state, "idle", "running", "awaiting_review") {
		i.State = state
	}
	return e.put("instances", id, i)
}
func (e *Engine) Disconnect(id string) error {
	ctx := WithActor(context.Background(), SystemActor("hook"))
	id = screenedIdentifier(id)
	e.mu.Lock()
	defer e.mu.Unlock()
	var i Instance
	if err := e.get("instances", id, &i); err != nil {
		return err
	}
	i.State = "disconnected"
	i.DisconnectReason = "session_end"
	i.Online = false
	if err := e.change(ctx, "instances", id, i, "instance.disconnect", AgentName(i.Agent)+" 会话已断开"); err != nil {
		return err
	}
	rs, err := e.Reviews()
	if err != nil {
		return err
	}
	for _, r := range rs {
		if r.InstanceID == id && r.Decision == "pending" {
			r.Decision = "reject"
			r.NeedsHuman = false
			r.Execution = "not_executed"
			r.RuleID = "E_SESSION"
			r.Comment = "原会话已结束，本次审查已取消。"
			now := e.clock()
			r.DecidedAt = &now
			if err = e.commitReview(ctx, r, "review.cancel"); err != nil {
				return err
			}
		}
	}
	return nil
}
func (e *Engine) Submit(in ReviewInput) (Review, error) {
	return e.SubmitContext(context.Background(), in)
}
func (e *Engine) submit(ctx context.Context, cancel context.CancelFunc, in ReviewInput) (Review, error) {
	// Direct callers share the HTTP boundary's value-free metadata contract.
	if in.PromptScan != nil && !in.PromptScan.valid() {
		return Review{}, invalidSecretMetadata
	}
	ctx = WithActor(ctx, SystemActor("hook"))
	// Native adapters bind reviews/results to the original opaque identifiers.
	key := sha256.Sum256([]byte(in.InstanceID + "\x00" + in.CallID))
	in.InstanceID = screenedIdentifier(in.InstanceID)
	e.mu.Lock()
	defer e.mu.Unlock()
	var i Instance
	if err := e.get("instances", in.InstanceID, &i); err != nil {
		return Review{}, errors.New("Agent 实例尚未注册")
	}
	if i.State == "disconnected" || e.clock().Sub(i.Heartbeat) > 30*time.Second {
		return Review{}, errors.New("Agent 实例已失联")
	}
	if in.CallID == "" || in.ToolName == "" || in.Arguments == nil {
		return Review{}, errors.New("审查参数缺失")
	}
	b, err := json.Marshal(struct {
		Tool       string
		Args       map[string]any
		Scripts    string
		PromptScan *PromptScan `json:",omitempty"`
	}{in.ToolName, in.Arguments, scriptDigest(in.ScriptCaptureStatus, in.Scripts), in.PromptScan})
	if err != nil {
		return Review{}, err
	}
	digest := sha256.Sum256(b)
	id := hex.EncodeToString(key[:])
	var existing Review
	if err = e.get("reviews", id, &existing); err == nil {
		if existing.Digest != hex.EncodeToString(digest[:]) {
			return Review{}, errors.New("工具调用标识已被不同参数使用")
		}
		return normalizeReviewPath(existing), nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Review{}, err
	}
	rules, err := e.Rules()
	if err != nil {
		return Review{}, err
	}
	scopes, err := e.Scopes()
	if err != nil {
		return Review{}, err
	}
	applicable := []Scope{}
	for _, s := range scopes {
		if s.NodeID == i.NodeID {
			applicable = append(applicable, s)
		}
	}
	protection, err := e.Protection()
	if err != nil {
		return Review{}, err
	}
	rules, err = compileProtection(protection, rules, applicable, i.NodeID)
	if err != nil {
		return Review{}, err
	}
	// Submit owns platform-aware evaluation and shares this list with every
	// downstream reviewer and snapshot, including local credential rules.
	resolve, contains := policyPath, within
	platform := runtime.GOOS
	if i.NodeID != "" {
		platform = i.Platform
		resolve = func(p, cwd string) string { return agentPath(p, cwd, i.Platform) }
		contains = func(root, p string) bool { return agentWithin(root, p, i.Platform) }
	}
	// Every adapter shares this boundary. Resolve deterministic policy against
	// the original arguments before redaction or either fallback reviewer.
	secretResult := secretSensitiveResult(ctx, in, rules)
	path := "scope"
	d := checkScopePaths(in, i.Cwd, applicable, resolve, contains)
	if d == nil {
		// XACML deny-overrides / deny-unless-permit; allow is non-terminal.
		acl := EvaluateACL(protection.EffectiveACLRules(), i.NodeID, protection.Tags[i.NodeID], in.ToolName)
		if acl.Effect == "deny" {
			path = "acl"
			d = &Decision{Decision: "reject", RuleID: acl.RuleID, Comment: "Tool access denied by ACL."}
		}
	}
	if d == nil {
		path = "rule"
		d = evaluatePathsSensitive(in, rules, i.Cwd, resolve, platform, secretResult)
	}
	original := promptAttackOriginal(in)
	paRules := promptAttackSelected(rules, in.ToolName)
	d, sensitive := reviewSensitiveContextResult(ctx, in, rules, e.Settings.BTPII, d, secretResult)
	baseline := d // PA evidence is not an authorization baseline.
	d, pa, paPending := reviewPromptAttack(original, paRules, d)
	if original.Surface != "prompt" && (d == nil || d.Decision != "reject") {
		d = baseline
	}
	if pa != nil && d != nil && hasPromptAttackFinding(*pa, d.RuleID) {
		path = "rule"
	}
	contentOmitted := false
	if sensitive != nil {
		if path != "acl" && d != nil && d.RuleID == sensitive.RuleID {
			path = "rule"
		}
		// A hit, skipped or unavailable detector cannot prove field-level safe
		// spans in the JSON envelope. Clean checks keep the existing retention.
		if len(sensitive.Findings) > 0 || sensitive.Unavailable || sensitive.Reason != "" {
			in = omitSensitiveInput(in)
			contentOmitted = true
			if d != nil {
				d.Comment = "Review content omitted by sensitive-info policy; rule " + eventIdentifier(d.RuleID)
			}
		}
	}
	forcedHuman := false
	if d != nil && hasExact(d.Decision, "approve", "alert") && in.ScriptCaptureStatus == "incomplete" {
		forcedHuman = true
		d = nil
	}
	s := e.Settings
	if s.NSFA.Mode == "enforce" && !e.nsfaEnforceAvailable(s.NSFA) {
		s.NSFA.Mode = "monitor"
	}
	if pa != nil && (s.NSFA.Mode == "monitor" || s.NSFA.Mode == "enforce") && (d == nil || d.Decision != "reject") {
		paPending = true
	}
	baseline = d
	if d != nil && d.Decision == "reject" {
		paPending = false
	}
	if in.ToolName == "prompt_turn" && d == nil && !paPending {
		d = &Decision{Decision: "approve", RuleID: "PA_CLEAN", Comment: "No prompt-attack rule requires further review."}
		path = "rule"
	}
	if paPending {
		d = nil
	}
	in.Arguments = Redact(in.Arguments).(map[string]any)
	in.UserMessage = RedactText(in.UserMessage)
	in.Context = RedactText(in.Context)
	// Screen only after digest/policy evaluation; retain correlation, not raw PANs.
	if !contentOmitted {
		in.CallID, in.ToolName = eventIdentifier(in.CallID), eventIdentifier(in.ToolName)
	}
	in.ScriptCaptureStatus = eventIdentifier(in.ScriptCaptureStatus)
	r := Review{Agent: AgentID(i.Agent), ID: id, ReviewInput: in, SessionID: screenedIdentifier(i.SessionID), Cwd: i.Cwd, Digest: hex.EncodeToString(digest[:]), Mode: s.Mode, Version: s.Version, Prompt: s.Prompt, ModelName: s.Model.Model, Rules: sensitiveRuleSnapshot(rules, contentOmitted), Scopes: applicable, Decision: "pending", Execution: "not_executed", CreatedAt: e.clock(), Deadline: e.clock().Add(time.Duration(s.ApprovalSeconds) * time.Second)}
	r.LogSuppression = logSuppression(protection, i.NodeID)
	r.SensitiveInfo = sensitive
	r.PromptAttack = pa
	r.PromptAttackNSFAMode = s.NSFA.Mode
	if d != nil {
		r.ReviewPath = path
		r.Decision = d.Decision
		if d.Decision == "alert" {
			r.Decision = "approve"
		}
		r.RuleID = d.RuleID
		r.Comment = RedactText(d.Comment)
		if privateIdentifier(r.Comment) {
			r.Comment = "Review metadata omitted by sensitive-info policy; rule " + eventIdentifier(d.RuleID)
		}
		now := e.clock()
		r.DecidedAt = &now
		if r.Decision == "approve" {
			r.Execution = "awaiting_execution"
		}
		// A rule hit is terminal: no human queue, model request or model usage.
		return e.commitReviewOutcome(ctx, r, "review.submit")
	}
	r.ReviewPath = s.Mode
	r.NeedsHuman = s.Mode == "human" || forcedHuman
	if forcedHuman {
		r.ReviewPath = "human"
		r.Comment = "脚本或外发文件未能完整采集，无法排除隐藏副作用，需要人工确认。"
	}
	if s.Mode == "model" && !forcedHuman && baseline == nil && original.Surface != "prompt" {
		s.Prompt = modelPrompt(s.Prompt)
		r.Prompt = s.Prompt
		// Explicitly record that no historical context was sent for this review.
		emptyContext := ""
		r.ModelContext = &emptyContext
		modelBytes, _ := json.Marshal(modelInput(r))
		r.ModelInput = modelBytes
		modelHash := sha256.Sum256(modelBytes)
		r.ModelInputDigest = hex.EncodeToString(modelHash[:])
		r.Deadline = e.clock().Add(time.Duration(s.ModelSeconds+5) * time.Second)
	}
	human := r.NeedsHuman && baseline == nil
	if paPending {
		r.ReviewPath = "model"
		r.NeedsHuman = false
	}
	if err = e.commitReview(ctx, r, "review.submit"); err != nil {
		return Review{}, err
	}
	if paPending {
		nsfa := e.promptAttackNSFA(s.NSFA)
		go e.promptAttackReview(ctx, cancel, r, s, original, paRules, baseline, human, nsfa)
	} else if r.ReviewPath == "model" {
		go e.promptAttackReview(ctx, cancel, r, s, original, nil, nil, false, nil)
	}
	return suppressedReview(r), nil
}

// Infer legacy paths from the saved verdict and rule snapshot, never today's
// rules or mode. Model verdict IDs can overlap builtin IDs (for example R1).
func normalizeReviewPath(r Review) Review {
	if r.ReviewPath != "" {
		return r
	}
	switch {
	case r.RuleID == "SCOPE_PATH" || r.RuleID == "SCOPE_TARGET":
		r.ReviewPath = "scope"
	case r.RuleID == "HUMAN" || r.NeedsHuman:
		r.ReviewPath = "human"
	case r.ModelVerdict != nil:
		r.ReviewPath = "model"
	default:
		r.ReviewPath = r.Mode
		for _, rule := range r.Rules {
			if rule.ID == r.RuleID && rule.Enabled && rule.Decision == r.Decision {
				r.ReviewPath = "rule"
				break
			}
		}
	}
	return r
}
func (e *Engine) Decide(ctx context.Context, id, digest, decision, comment string) (Review, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := e.Review(id)
	if err != nil {
		return r, err
	}
	if r.Digest != digest {
		return r, errors.New("参数摘要不匹配")
	}
	if !hasExact(decision, "approve", "reject") {
		return r, errors.New("无效裁决")
	}
	if r.PromptAttack != nil && r.ReviewPath == "model" && !r.NeedsHuman && r.Decision == "pending" {
		return r, errors.New("Prompt-attack detection is pending")
	}
	if r.Mode != "human" && r.ReviewPath != "human" {
		return r, errors.New("此调用不属于人工审批")
	}
	if r.Decision != "pending" {
		if r.Decision == decision && r.RuleID == "HUMAN" {
			return r, nil
		}
		return r, errors.New("此调用已裁决或已失效")
	}
	if e.clock().After(r.Deadline) {
		return r, errors.New("审批已过期")
	}
	if decision == "reject" && comment == "" {
		return r, errors.New("请填写拒绝原因")
	}
	r.Decision = decision
	r.NeedsHuman = false
	r.RuleID = "HUMAN"
	if comment == "" {
		comment = "人工批准本次工具调用"
	}
	r.Comment = RedactText(comment)
	now := e.clock()
	r.DecidedAt = &now
	if decision == "approve" {
		r.Execution = "awaiting_execution"
	}
	return e.commitReviewOutcome(ctx, r, "review.human")
}
func (e *Engine) Result(id, instance, state, result string, findings ...ClientSecretFinding) error {
	ctx := WithActor(context.Background(), SystemActor("hook"))
	instance = screenedIdentifier(instance)
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := e.Review(id)
	if err != nil {
		return err
	}
	if r.InstanceID != instance {
		return errors.New("实例不匹配")
	}
	if r.Decision == "pending" {
		return errors.New("尚未裁决")
	}
	// Output-only secret rejections already have a captured/omitted result;
	// their retries cannot confirm that the original approved call was blocked.
	if r.Decision == "reject" && r.Execution == "not_executed" && reviewOutputState(r) == ContentNeverCaptured {
		if state != "not_executed" {
			return errors.New("被拒绝的调用不能报告执行成功")
		}
		if r.BlockConfirmed {
			return nil
		}
		// Execution was preset by policy. Persist adapter confirmation and its
		// immutable events together; a failed audit leaves the retry unconsumed.
		r.BlockConfirmed = true
		return e.commitReview(ctx, r, "review.result")
	}
	if !hasExact(state, "succeeded", "failed", "not_executed") {
		return errors.New("无效执行结果")
	}
	if r.Execution != "awaiting_execution" {
		if r.Execution == state {
			return nil
		}
		return errors.New("执行结果已终结")
	}
	// Result hooks are observational: a rejection below blocks retention, not
	// the tool action that has already occurred; preserve the actual execution state.
	rules, err := e.Rules()
	if err != nil {
		return err
	}
	scopes, err := e.Scopes()
	if err != nil {
		return err
	}
	var instanceRecord Instance
	if err = e.get("instances", instance, &instanceRecord); err != nil {
		return err
	}
	applicable := []Scope{}
	for _, scope := range scopes {
		if scope.NodeID == instanceRecord.NodeID {
			applicable = append(applicable, scope)
		}
	}
	rules, err = e.protectionRules(rules, applicable, instanceRecord.NodeID)
	if err != nil {
		return err
	}
	// OWASP LLM06 applies to output too. Reuse the same local matcher and privacy
	// projection without a remote detector or a claim of client-side rewriting.
	output := ReviewInput{ToolName: r.ToolName, Arguments: map[string]any{"result": result}}
	rawResult := secretSensitiveResult(ctx, output, rules)
	sensitive := rawResult
	if len(findings) > 0 {
		// The bridge already masked original result leaves. Reuse prompt_scan's
		// validated, value-free metadata consumption without persisting it as input.
		output.PromptScan = &PromptScan{Status: secrets.Complete, Findings: findings}
		sensitive = secretSensitiveResult(ctx, output, rules)
	}
	if sensitive != nil {
		if r.SensitiveInfo != nil {
			sensitive.Findings = append(sensitive.Findings, r.SensitiveInfo.Findings...)
		}
		r.SensitiveInfo = sensitive
		// Preserve the legacy raw-result retention verdict. Metadata-only output
		// observations must not rewrite the authorization issued before execution.
		if rawResult != nil {
			now := e.clock()
			r.DecidedAt = &now
			r.Decision, r.RuleID, r.ReviewPath = "reject", rawResult.RuleID, "rule"
			r.Comment = "Credential pattern detected in observed result; content omitted."
		}
		// Submit already screened these persisted identifiers. Keep their input/
		// result correlation instead of hashing an existing digest a second time.
		tool, call := r.ToolName, r.CallID
		r.ReviewInput = omitSensitiveInput(r.ReviewInput)
		r.ToolName, r.CallID = tool, call
		r.Rules = sensitiveRuleSnapshot(rules, true)
	}
	selected := promptAttackSelected(rules, r.ToolName)
	if len(selected) > 0 && r.Decision != "reject" {
		bounded, cancel := context.WithTimeout(ctx, ReviewHookBudget)
		defer cancel()
		settings := e.Settings
		if settings.NSFA.Mode == "enforce" && !e.nsfaEnforceAvailable(settings.NSFA) {
			settings.NSFA.Mode = "monitor"
		}
		detected, err := (PromptAttackDetector{Settings: settings, Rules: selected, Tool: r.ToolName, NSFA: e.promptAttackNSFA(settings.NSFA)}).Detect(bounded, PromptAttackInput{Text: result, Surface: "tool_result", Tenant: eventTenant()})
		if err != nil {
			return err
		}
		r.PromptAttack = &detected
		r.PromptAttackNSFAMode = settings.NSFA.Mode
		r.Rules = sensitiveRuleSnapshot(rules, r.SensitiveInfo != nil)
	}

	r.Execution = state
	r.Result = RedactText(result)
	if r.SensitiveInfo != nil {
		r.Result = "[REDACTED]"
	} // Passive result hook, never claim a client rewrite.
	return e.commitReview(ctx, r, "review.result")
}
func (e *Engine) LocalDiagnostic() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	return map[string]any{"version": Version, "mode": e.Settings.Mode, "dataDir": e.Dir, "modelConfigured": e.Settings.Model.Tested, "toolBoundary": "Pi tool_call；不包含脚本内部子调用、其它扩展 pi.exec 或用户 ! 命令"}
}
func (e *Engine) ExportCalls() ([]byte, error) {
	rs, err := e.Reviews()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(rs, "", "  ")
}
func (e *Engine) Secret(name string) (string, error) {
	path := filepath.Join(e.Dir, name+".token")
	b, err := os.ReadFile(path)
	if err == nil {
		return string(b), nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	token := ID() + ID()
	if err = AtomicFile(path, []byte(token), 0600); err != nil {
		return "", fmt.Errorf("保存令牌失败: %w", err)
	}
	return token, nil
}
