// Package bridge implements native command hook protocols without opening the server database.
package bridge

import (
	"aegishook/internal/core"
	"aegishook/internal/localaddr"
	"aegishook/internal/secrets"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Config shares the enrollment contract, including its pinned verification key.
type Config = core.ClientConnection
type client struct {
	cfg  Config
	http *http.Client
}

func (c client) request(ctx context.Context, path string, body any, out any) error {
	method := "GET"
	var data []byte
	if body != nil {
		method = "POST"
		data, _ = json.Marshal(body)
		if _, ok := body.(core.ToolOutputRequest); ok && len(data) > core.ToolOutputJSONBytes {
			return core.ErrToolOutputOversized
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.Endpoint+"/api/v1"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	if path == "/reviews" {
		if deadline, ok := ctx.Deadline(); ok {
			req.Header.Set("X-TG-Expected-Rq-Timeout-Ms", fmt.Sprint(max(int64(1), time.Until(deadline).Milliseconds())))
		}
	}
	res, err := c.http.Do(req)
	if err != nil {
		return errors.New("审查服务连接失败")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("审查服务返回 HTTP %d", res.StatusCode)
	}
	if transformed, ok := out.(*core.ToolOutputResponse); ok {
		data, err := core.ReadToolOutputJSON(res.Body)
		if err != nil {
			return err
		}
		response, err := core.DecodeToolOutputResponse(data)
		if err != nil {
			return err
		}
		*transformed = response
		return nil
	}
	if out != nil {
		decoder := json.NewDecoder(io.LimitReader(res.Body, 2<<20))
		if err := decoder.Decode(out); err != nil {
			return err
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return errors.New("审查服务返回非法 JSON")
		}
	}
	return nil
}
func text(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
func hash(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}
func eventName(m map[string]any) string { return text(m, "hook_event_name", "hookEventName") }
func decisionOutput(agent, decision, reason string, out io.Writer) {
	if agent == "cursor" {
		cursorDecisionOutput(decision, reason, out)
		return
	}
	if agent == "grok" {
		json.NewEncoder(out).Encode(map[string]any{"decision": map[string]string{"approve": "allow", "reject": "deny"}[decision], "reason": reason})
		return
	}
	if agent == "opencode" || agent == "pi" {
		json.NewEncoder(out).Encode(map[string]any{"decision": decision, "comment": reason})
		return
	}
	if decision == "approve" {
		// An AegisHook permit must not bypass the client's own permissions.
		fmt.Fprintln(out, "{}")
		return
	}
	json.NewEncoder(out).Encode(map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}})
}

// Run always emits an explicit denial and exit 2 when a pre-tool review cannot complete.
func Run(agent, connection string, in io.Reader, out, stderr io.Writer) int {
	started := time.Now()
	agent = core.AgentID(agent)
	hookTimeout := 24*time.Hour + time.Minute
	if agent == "claude" || agent == "cursor" || agent == "codex" {
		// core.ReviewHookBudget: AgentSentry 4500ms IPC budget below its 5-second command-hook timeout
		// (docs/research/ENDPOINT-RUNTIME-AgentSentry.md §§4–5).
		hookTimeout = core.ReviewHookBudget
	}
	ctx, cancel := context.WithDeadline(context.Background(), started.Add(hookTimeout))
	defer cancel()
	type result struct {
		code        int
		output, log string
	}
	done := make(chan result, 1)
	go func() {
		// Non-cancellable local I/O may outlive Run. Never let it write a late permit.
		var output, log bytes.Buffer
		code := run(ctx, agent, connection, in, &output, &log)
		done <- result{code, output.String(), log.String()}
	}()
	select {
	case got := <-done:
		if ctx.Err() != nil {
			return denyOutput(agent, ctx.Err(), out, stderr)
		}
		fmt.Fprint(out, got.output)
		fmt.Fprint(stderr, got.log)
		return got.code
	case <-ctx.Done():
		return denyOutput(agent, ctx.Err(), out, stderr)
	}
}

func denyOutput(agent string, err error, out, stderr io.Writer) int {
	reason := "AegisHook 拒绝执行：" + err.Error()
	decisionOutput(agent, "reject", reason, out)
	fmt.Fprintln(stderr, reason)
	return 2
}

// UserPromptSubmit exit 2 blocks Claude prompt processing even before /reviews.
// https://code.claude.com/docs/en/hooks#exit-code-2-behavior
func promptDenyOutput(agent, reason string, out, stderr io.Writer) int {
	if agent == "cursor" {
		cursorDecisionOutput("reject", reason, out)
	} else {
		json.NewEncoder(out).Encode(map[string]string{"decision": "block", "reason": reason})
	}
	fmt.Fprintln(stderr, reason)
	return 2
}

func run(ctx context.Context, agent, connection string, in io.Reader, out, stderr io.Writer) (code int) {
	deny := func(err error) int { return denyOutput(agent, err, out, stderr) }
	defer func() {
		if recover() != nil {
			code = deny(errors.New("Hook 内部异常"))
		}
	}()
	events, ok := familyHookEvents[agent]
	if !ok {
		return deny(errors.New("未知客户端"))
	}
	var m map[string]any
	decoder := json.NewDecoder(io.LimitReader(in, 2<<20))
	if err := decoder.Decode(&m); err != nil || m == nil {
		return deny(errors.New("Hook 输入不是 JSON 对象"))
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return deny(errors.New("Hook 输入含多余内容"))
	}
	event := eventName(m)
	// Validate native names before config access, normalization or advisory failures.
	if !contains(event, events.handled...) {
		if !contains(event, events.advisory...) {
			return deny(fmt.Errorf("unsupported %s hook event", core.AgentName(agent)))
		}
		return 0 // Documented but unregistered events have no bridge side effects.
	}
	if agent == "cursor" || agent == "pi" {
		var err error
		if agent == "pi" {
			m, err = normalizePi(m)
		} else {
			m, err = normalizeCursor(m)
		}
		if err != nil {
			return deny(err)
		}
		event = eventName(m)
	}
	pre := event == "PreToolUse"
	var bundle *core.PolicyBundle
	fail := func(err error) int {
		if event == "UserPromptSubmit" && (agent == "claude" || agent == "cursor") {
			return promptDenyOutput(agent, "Prompt-attack review unavailable", out, stderr)
		}
		if pre || event == "" {
			// Cached rules can explain/add a denial, never supply an offline
			// permit. Reachable server decisions retain their existing authority.
			if bundle != nil {
				args, _ := m["tool_input"].(map[string]any)
				if args == nil {
					args, _ = m["toolInput"].(map[string]any)
				}
				input := core.ReviewInput{ToolName: text(m, "tool_name", "toolName"), Arguments: args}
				if d := core.PolicyBundleDeny(*bundle, input, text(m, "cwd", "workspaceRoot")); d != nil {
					return deny(errors.New("cached policy: " + core.RedactText(d.Comment)))
				}
			}
			return deny(err)
		}
		fmt.Fprintln(stderr, "AegisHook："+err.Error())
		return 1
	}
	var cfg Config
	b, err := readConnection(connection)
	if err != nil || json.Unmarshal(b, &cfg) != nil {
		return fail(errors.New("无法读取 Hook 连接配置"))
	}
	endpoint, err := localaddr.Endpoint(cfg.Endpoint)
	if err != nil || cfg.Token == "" {
		return fail(errors.New("Hook 连接地址或凭据无效：远程须使用 HTTPS"))
	}
	cfg.Endpoint = endpoint
	requestTimeout := 2500 * time.Millisecond
	if (agent == "claude" || agent == "cursor" || agent == "codex") && (pre || event == "UserPromptSubmit") {
		requestTimeout = core.ReviewHookBudget
	}
	c := client{cfg: cfg, http: &http.Client{Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("禁止重定向") }}}
	session := text(m, "session_id", "sessionId", "sessionID")
	cwd := text(m, "cwd", "workspaceRoot")
	if session == "" || !filepath.IsAbs(cwd) {
		return fail(errors.New("缺少会话 ID 或绝对工作目录"))
	}
	if real, err := filepath.EvalSymlinks(cwd); err == nil {
		cwd = real
	}
	instance := hash(agent, session, cwd)
	if cfg.NodeID != "" {
		instance = hash(cfg.NodeID, agent, session, cwd)
	}
	if event == "SessionEnd" {
		return passive(c.request(ctx, "/instances/"+instance+"/shutdown", map[string]any{}, nil), stderr)
	}
	if !contains(event, "PreToolUse", "PostToolUse", "PostToolUseFailure", "SessionStart", "UserPromptSubmit") {
		return fail(errors.New("不支持的 Hook 事件"))
	}
	if pre && cfg.NodeID != "" {
		bundle, err = c.policyBundle(ctx, filepath.Join(filepath.Dir(connection), "bundle.json"))
		if err != nil {
			return fail(err)
		}
	}
	state := "idle"
	if agent == "pi" && event == "SessionStart" {
		state = text(m, "state") // normalizePi validates the existing activity enum.
	}
	heartbeat := func() error {
		return c.request(ctx, "/instances/"+instance+"/heartbeat", map[string]any{"state": state}, nil)
	}
	if err = heartbeat(); err != nil {
		mode := "events"
		if agent == "pi" {
			// Pi owns an in-process session lease/heartbeat, unlike command hooks.
			// Preserve Installations' loaded/waiting_reload semantics.
			mode = ""
		}
		err = c.request(ctx, "/instances", core.Instance{ID: instance, NodeID: cfg.NodeID, Platform: runtime.GOOS, Agent: agent, AgentVersion: text(m, "agent_version"), SessionID: session, Cwd: cwd, HookVersion: core.Version, ConnectionMode: mode}, nil)
		if err != nil {
			return fail(err)
		}
		if state != "idle" {
			if err = heartbeat(); err != nil {
				return fail(err)
			}
		}
	}
	contextPath := filepath.Join(filepath.Dir(connection), "context-"+instance+".json")
	if event == "UserPromptSubmit" {
		rawPrompt := text(m, "prompt", "userMessage")
		saved := scanPrompt(ctx, rawPrompt)
		message := rawPrompt
		if saved.PromptScan != nil {
			message = saved.UserMessage
		}
		var review core.Review
		call := hash("prompt", rawPrompt)
		err := c.request(ctx, "/reviews", secretReviewInput{ReviewInput: core.ReviewInput{InstanceID: instance, CallID: call, ToolName: "prompt_turn", Arguments: map[string]any{}, UserMessage: message}, PromptScan: saved.PromptScan}, &review)
		// Q4: Codex/OpenCode do not document prompt-submit blocking. Detection only.
		blocking := agent == "claude" || agent == "cursor"
		if err == nil && blocking {
			for review.Decision == "pending" {
				select {
				case <-ctx.Done():
					err = ctx.Err()
				case <-time.After(500 * time.Millisecond):
					err = c.request(ctx, "/reviews/"+hash(instance, call)+"?instanceId="+instance, nil, &review)
				}
				if err != nil {
					break
				}
			}
		}
		if blocking && (err != nil || review.ID != hash(instance, call) || review.Decision != "approve") {
			reason := "Prompt-attack review unavailable"
			if err == nil && review.Comment != "" {
				reason = review.Comment
			}
			return promptDenyOutput(agent, reason, out, stderr)
		}
		code := passive(core.AtomicFile(contextPath, mustJSON(saved), 0600), stderr)
		if agent == "cursor" && code == 0 {
			fmt.Fprintln(out, `{"continue":true}`)
		}
		return code
	}
	if event == "SessionStart" {
		fmt.Fprintln(out, "{}")
		return 0
	}
	callID := text(m, "tool_use_id", "toolUseId", "toolCallId", "callID")
	tool := text(m, "tool_name", "toolName")
	args, _ := m["tool_input"].(map[string]any)
	if args == nil {
		args, _ = m["toolInput"].(map[string]any)
	}
	if !pre {
		if callID == "" {
			fmt.Fprintln(stderr, "AegisHook：客户端未提供调用 ID，保留执行结果未知")
			return 0
		}
		state, original := resultState(agent, event, m)
		if state == "" {
			fmt.Fprintln(stderr, "AegisHook：没有可确认的执行结果，保留等待状态")
			return 0
		}
		leaves, status := secrets.ScanTree(ctx, original, "tool_result")
		if status == secrets.Interrupted {
			return fail(errors.New("Secret scan interrupted"))
		}
		safe := omitSecretLeaves(original, "", leaves)
		result := core.RedactText(string(mustJSON(safe)))
		if event == "PostToolUseFailure" {
			result = core.RedactText(safe.(string))
		}
		report := map[string]any{"instanceId": instance, "state": state, "result": result}
		if len(leaves) > 0 {
			report["findings"] = leaves
		}
		err = c.request(ctx, "/reviews/"+hash(instance, callID)+"/result", report, nil)
		return passive(err, stderr)
	}
	if callID == "" {
		if agent != "grok" {
			return deny(errors.New("客户端未提供工具调用 ID"))
		}
		callID = core.ID()
	}
	if tool == "" || args == nil {
		return deny(errors.New("工具名称或参数对象缺失"))
	}
	scriptFiles, scriptStatus := core.CaptureScripts(cwd, tool, args)
	outgoingFrom := len(scriptFiles)
	// A file-reading tool sends a local path, not its bytes; capture the file it
	// is about to hand over into the same snapshot carrier (plan #24 slice 1).
	// D5 limits this to the clients whose hook contract documents the scalar
	// path field, so another client's Read stays exactly as before.
	if agent == "claude" || agent == "cursor" {
		scriptFiles, scriptStatus = core.CaptureOutgoingFiles(cwd, tool, args, scriptFiles, scriptStatus)
	}
	input := secretReviewInput{ReviewInput: core.ReviewInput{InstanceID: instance, CallID: callID, ToolName: tool, Arguments: args, UserMessage: text(m, "userMessage"), Context: text(m, "context"), Scripts: scriptFiles, ScriptCaptureStatus: scriptStatus}}
	if input.UserMessage == "" {
		var saved cachedPrompt
		if b, err = os.ReadFile(contextPath); err == nil && json.Unmarshal(b, &saved) == nil {
			input.UserMessage, input.PromptScan = saved.UserMessage, saved.PromptScan
		}
	}
	// A capture that would exceed the review transport body is recorded
	// content-free instead of being sent and rejected (plan #24 D2).
	core.FitOutgoingFileSnapshot(&input.ReviewInput, outgoingFrom, len(mustJSON(input)))
	var review struct {
		ID         string    `json:"id"`
		Decision   string    `json:"decision"`
		Comment    string    `json:"comment"`
		RuleID     string    `json:"ruleId"`
		Execution  string    `json:"execution"`
		ReviewPath string    `json:"reviewPath"`
		Deadline   time.Time `json:"deadline"`
	}
	if err = c.request(ctx, "/reviews", input, &review); err != nil {
		return deny(err)
	}
	expected := hash(instance, callID)
	lastBeat := time.Now()
	for {
		if review.ID != expected || !contains(review.Decision, "approve", "reject", "pending") || review.Deadline.IsZero() {
			return deny(errors.New("服务返回非法裁决"))
		}
		if review.Decision != "pending" {
			if review.Comment == "" || review.RuleID == "" || (review.Decision == "approve" && review.Execution != "awaiting_execution") {
				return deny(errors.New("裁决字段不完整或调用已经执行"))
			}
			break
		}
		if (agent == "claude" || agent == "cursor") && review.ReviewPath == "human" {
			return deny(errors.New("pending approval in TG-Sentry console; retry after approval"))
		}
		if time.Now().After(review.Deadline.Add(time.Second)) {
			return deny(errors.New("审查等待超时"))
		}
		select {
		case <-ctx.Done():
			return deny(errors.New("Hook 等待结束"))
		case <-time.After(500 * time.Millisecond):
		}
		if time.Since(lastBeat) > 8*time.Second {
			if err = c.request(ctx, "/instances/"+instance+"/heartbeat", map[string]any{"state": "awaiting_review"}, nil); err != nil {
				return deny(err)
			}
			lastBeat = time.Now()
		}
		review.ID = ""
		review.Decision = ""
		review.Comment = ""
		review.RuleID = ""
		review.Execution = ""
		review.ReviewPath = ""
		review.Deadline = time.Time{}
		if err = c.request(ctx, "/reviews/"+expected+"?instanceId="+instance, nil, &review); err != nil {
			return deny(err)
		}
	}
	if review.Decision == "reject" {
		return deny(errors.New(review.Comment))
	}
	decisionOutput(agent, "approve", review.Comment, out)
	return 0
}

// D2 uses one atomic context-file write: marker plus metadata, never candidates.
// Clean/legacy caches omit prompt_scan. The wire shape is the plan §3.6 location
// contract; secrets.Leaf keeps its cleartext Path and RuleID out of JSON.
type promptScan struct {
	Status   secrets.Status `json:"status"`
	Findings []secrets.Leaf `json:"findings"`
}
type cachedPrompt struct {
	UserMessage string      `json:"userMessage"`
	PromptScan  *promptScan `json:"prompt_scan,omitempty"`
}
type secretReviewInput struct {
	core.ReviewInput
	PromptScan *promptScan `json:"prompt_scan,omitempty"`
}

func scanPrompt(ctx context.Context, original string) cachedPrompt {
	findings, status := secrets.Scan(ctx, original)
	if status == secrets.Complete && len(findings) == 0 {
		return cachedPrompt{UserMessage: core.RedactText(original)}
	}
	scan := &promptScan{Status: status, Findings: []secrets.Leaf{}}
	for _, finding := range findings {
		scan.Findings = append(scan.Findings, secrets.Leaf{Finding: finding,
			Surface: "prompt", Kind: "value", FieldDigest: hash("")})
	}
	return cachedPrompt{UserMessage: "[REDACTED]", PromptScan: scan}
}

func omitSecretLeaves(v any, path string, leaves []secrets.Leaf) any {
	if len(leaves) == 0 {
		return v
	}
	hits := make(map[string]bool)
	for _, leaf := range leaves {
		hits[leaf.Kind+":"+leaf.Path] = true
	}
	return omitSecretTree(v, path, hits)
}

// Mirror ScanTree's dotted paths. Ambiguous dotted keys conservatively omit
// every matching leaf rather than risking retaining one of the candidates.
func omitSecretTree(v any, path string, hits map[string]bool) any {
	if hits["value:"+path] {
		return "[REDACTED]"
	}
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for key, value := range x {
			child := key
			if path != "" {
				child = path + "." + child
			}
			if hits["key:"+child] {
				out["[REDACTED]"] = "[REDACTED]"
				continue
			}
			out[key] = omitSecretTree(value, child, hits)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, value := range x {
			child := strconv.Itoa(i)
			if path != "" {
				child = path + "." + child
			}
			out[i] = omitSecretTree(value, child, hits)
		}
		return out
	default:
		return v
	}
}

func readConnection(path string) ([]byte, error) {
	// Stat follows symlinks: a link to a regular file stays valid, a link to a FIFO is refused.
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("Hook connection must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err = f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("Hook connection must be a regular file")
	}
	return io.ReadAll(f)
}

func passive(err error, stderr io.Writer) int {
	if err != nil {
		fmt.Fprintln(stderr, "AegisHook："+err.Error())
		return 1
	}
	return 0
}
func contains(s string, vs ...string) bool {
	for _, v := range vs {
		if s == v {
			return true
		}
	}
	return false
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// resultState preserves original leaves; the caller scans before masking or JSON encoding.
func resultState(agent, event string, m map[string]any) (string, any) {
	v := m["tool_response"]
	if v == nil {
		v = m["toolResponse"]
	}
	if v == nil {
		v = m["result"]
	}
	result := v
	if event == "PostToolUseFailure" {
		if agent == "cursor" && text(m, "failure_type") == "permission_denied" {
			return "not_executed", text(m, "error")
		}
		return "failed", text(m, "error")
	}
	if s := text(m, "executionState"); (agent == "opencode" || agent == "pi") && contains(s, "succeeded", "failed", "not_executed") {
		return s, result
	}
	if agent == "claude" || agent == "grok" || agent == "cursor" {
		return "succeeded", result
	}
	obj, ok := v.(map[string]any)
	if !ok {
		if s, ok := v.(string); ok {
			json.Unmarshal([]byte(s), &obj)
		}
	}
	for _, k := range []string{"isError", "is_error"} {
		if value, ok := obj[k].(bool); ok {
			if value {
				return "failed", result
			}
			return "succeeded", result
		}
	}
	for _, k := range []string{"exit_code", "exitCode"} {
		if value, ok := obj[k].(float64); ok {
			if value != 0 {
				return "failed", result
			}
			return "succeeded", result
		}
	}
	// Codex shell output embeds an explicit exit status; do not infer success from text alone.
	if s, ok := v.(string); ok {
		for _, line := range strings.Split(s, "\n") {
			var status int
			if n, _ := fmt.Sscanf(line, "Process exited with code %d", &status); n == 1 {
				if status != 0 {
					return "failed", result
				}
				return "succeeded", result
			}
		}
	}
	return "", result
}
