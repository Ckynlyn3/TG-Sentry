package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"aegishook/internal/secrets"

	"mvdan.cc/sh/v3/syntax"
)

var secretKey = regexp.MustCompile(`(?i)(password|passwd|secret|token|api.?key|authorization|cookie|credential)`)
var textSecrets = regexp.MustCompile(`(?i)((?:password|passwd|token|api[_-]?key|secret|authorization)\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s,;&]+)`)
var flagSecrets = regexp.MustCompile(`(?i)((?:--?(?:password|passwd|token|api[_-]?key|secret)|-p)\s+)(?:"[^"]*"|'[^']*'|[^\s,;&]+)`)
var jsonSecrets = regexp.MustCompile(`(?i)("(?:password|passwd|secret|token|api.?key|authorization|cookie|credential)"\s*:\s*)"(?:[^"\\]|\\.)*"`)
var urlSecrets = regexp.MustCompile(`(?i)(https?://)[^\s/@:]+:[^\s/@]+@`)
var bearer = regexp.MustCompile(`(?i)\bBearer\s+[a-z0-9._~+/-]+`)

func RedactText(s string) string {
	// Reuse the frozen detector at the existing privacy boundary as well as the
	// enforcing matcher: free-text comments/metadata can contain bare credentials.
	if findings, status := secrets.Scan(context.Background(), s); status != secrets.Complete || len(findings) > 0 {
		return "[REDACTED]"
	}
	s = bearer.ReplaceAllString(s, "Bearer [REDACTED]")
	s = jsonSecrets.ReplaceAllString(s, `${1}"[REDACTED]"`)
	s = flagSecrets.ReplaceAllString(s, "${1}[REDACTED]")
	s = urlSecrets.ReplaceAllString(s, "${1}[REDACTED]@")
	s = textSecrets.ReplaceAllString(s, "${1}[REDACTED]")
	s = bearer.ReplaceAllString(s, "Bearer [REDACTED]")
	if len(s) > 24000 {
		s = s[:24000] + "…[truncated]"
	}
	return s
}
func Redact(v any) any {
	switch x := v.(type) {
	case map[string]any:
		o := map[string]any{}
		for k, v := range x {
			if secretKey.MatchString(k) {
				o[k] = "[REDACTED]"
			} else {
				o[k] = Redact(v)
			}
		}
		return o
	case []any:
		o := make([]any, len(x))
		for i, v := range x {
			o[i] = Redact(v)
		}
		return o
	case string:
		return RedactText(x)
	default:
		return v
	}
}
func BuiltinRules() []Rule {
	names := []string{"禁止修改密码及登录状态", "禁止修改目标系统配置", "禁止修改账号与权限", "禁止破坏关键数据和文件", "禁止停止或重启业务服务", "禁止明确的拒绝服务操作"}
	out := []Rule{}
	for i, n := range names {
		out = append(out, Rule{ID: fmt.Sprintf("R%d", i+1), Name: n, Decision: "reject", Enabled: true, Builtin: true, Matcher: "semantic", Target: "arguments"})
	}
	out = append(out, Rule{ID: "A7", Name: "读取与查询工具", Decision: "approve", Enabled: true, Builtin: true, Matcher: "semantic", Target: "arguments"})
	for _, preset := range detailedRuleCatalog {
		out = append(out, Rule{ID: preset.id, Name: preset.name, Decision: "reject", Enabled: !preset.optIn, Builtin: true, Matcher: "semantic", Target: "arguments", Priority: preset.priority})
	}
	out = append(out, secretRules()...)
	out = append(out, sensitiveInfoRules()...)
	out = append(out, promptAttackRules()...)
	for i := range out {
		out[i] = normalizeRule(out[i])
	}
	return out
}

// Frozen Gitleaks subset from internal/secrets/rules.go (plan §3.1).
// R_SECRET_ follows the existing R_PII_ built-in naming convention.
func secretRules() []Rule {
	var out []Rule
	for _, entity := range []string{"aws-access-token", "github-pat", "github-fine-grained-pat", "gitlab-pat", "openai-api-key", "anthropic-api-key", "anthropic-admin-api-key", "private-key", "jwt"} {
		out = append(out, Rule{ID: "R_SECRET_" + strings.ToUpper(strings.ReplaceAll(entity, "-", "_")), Name: "Credential pattern: " + entity,
			Matcher: "secret", Pattern: entity, Target: "arguments", Builtin: true, Enabled: true, Decision: "reject", Categories: []string{SensitiveInfoCategory}})
	}
	return out
}

// Like semantic dispatch, template copies resolve the server-owned definition
// by source identity, never by a caller-supplied pattern or compiled T_ ID.
func secretRulePattern(r Rule) string {
	if !r.Builtin || r.Matcher != "secret" {
		return ""
	}
	id := r.ID
	if r.SourceRuleID != "" {
		id = r.SourceRuleID
	}
	for _, preset := range secretRules() {
		if preset.ID == id {
			return preset.Pattern
		}
	}
	return ""
}

func reject(id, what string) *Decision {
	return &Decision{Decision: "reject", RuleID: id, Comment: "实际操作：" + what + "；成功后的后果：可能改变受保护的系统状态；命中规则：" + id + "。请改用只读验证方式。"}
}
func valueAt(m map[string]any, path string) any {
	var v any = m
	for _, p := range strings.Split(path, ".") {
		o, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = o[p]
	}
	return v
}
func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}
func has(s string, patterns ...string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}
func builtinMatches(input ReviewInput, cwd string) (map[string]string, bool) {
	return builtinMatchesPaths(input, cwd, policyPath, runtime.GOOS)
}
func builtinMatchesPaths(input ReviewInput, cwd string, resolve func(string, string) string, platform string) (map[string]string, bool) {
	hits := map[string]string{}
	parseFailed := false
	add := func(id, what string) { hits[id] = what }
	name := strings.ToLower(input.ToolName)
	b, _ := json.Marshal(input.Arguments)
	raw := strings.ToLower(string(b))
	cmd := argumentText(input.Arguments, "command", "cmd")
	// Only confident effects trigger hard rules. Opaque programs fall through to the configured reviewer.
	if has(name, "reset_password", "change_password", "set_password", "logout_user") {
		add("R1", "修改密码或用户登录状态")
	}
	if has(name, "create_user", "delete_user", "update_user", "create_role", "delete_role", "grant_permission") {
		add("R3", "修改账号或权限")
	}
	method := strings.ToUpper(fmt.Sprint(input.Arguments["method"]))
	requestURL := fmt.Sprint(input.Arguments["url"])
	if method != "GET" && method != "HEAD" && method != "<nil>" {
		if regexp.MustCompile(`(?i)/(password|reset-password|logout)(/|\?|$)`).MatchString(requestURL) {
			add("R1", "通过接口修改密码或登录状态")
		}
		if regexp.MustCompile(`(?i)/(users|accounts|roles|permissions)(/|\?|$)`).MatchString(requestURL) {
			add("R3", "通过接口修改账号或权限")
		}
	}
	if name == "write" || name == "edit" {
		p := argumentText(input.Arguments, "path", "file_path", "filePath")
		if protectedPath(resolve(p, cwd), platform) {
			add("R2", "写入系统配置文件")
		}
	}
	if name == "bash" || cmd != "" {
		tree, err := syntax.NewParser().Parse(strings.NewReader(cmd), "")
		parseFailed = err != nil
		if err == nil {
			syntax.Walk(tree, func(n syntax.Node) bool {
				if red, ok := n.(*syntax.Redirect); ok && red.Word != nil {
					if red.Op == syntax.RdrOut || red.Op == syntax.AppOut || red.Op == syntax.RdrAll || red.Op == syntax.AppAll {
						if protectedPath(resolve(literalWord(red.Word), cwd), platform) {
							add("R2", "重定向写入系统配置")
						}
					}
				}
				c, ok := n.(*syntax.CallExpr)
				if !ok || len(c.Args) == 0 {
					return true
				}
				words := []string{}
				for _, w := range c.Args {
					words = append(words, literalWord(w))
				}
				exe := strings.ToLower(filepath.Base(words[0]))
				args := strings.ToLower(strings.Join(words[1:], " "))
				if exe == "sudo" && len(words) > 1 {
					exe = strings.ToLower(filepath.Base(words[1]))
					args = strings.ToLower(strings.Join(words[2:], " "))
				}
				switch exe {
				case "passwd", "chpasswd", "set-localuser":
					add("R1", "修改用户密码")
				case "useradd", "userdel", "usermod", "adduser", "deluser", "groupadd", "groupdel", "groupmod", "dscl", "new-localuser", "remove-localuser", "rename-localuser", "enable-localuser", "disable-localuser", "new-localgroup", "remove-localgroup", "add-localgroupmember", "remove-localgroupmember":
					add("R3", "修改系统账号或用户组")
				case "shutdown", "reboot", "halt", "poweroff", "killall", "pkill", "stop-service", "restart-service", "stop-process", "stop-computer", "restart-computer":
					add("R5", "停止系统或业务进程")
				case "systemctl", "service", "launchctl":
					if regexp.MustCompile(`\b(stop|restart|disable|unload|bootout)\b`).MatchString(args) {
						add("R5", "停止或重启业务服务")
					}
				case "set-service", "set-netfirewallprofile", "new-netfirewallrule", "remove-netfirewallrule", "register-scheduledtask", "unregister-scheduledtask", "set-scheduledtask":
					add("R2", "修改 Windows 服务、防火墙或计划任务配置")
				case "crontab":
					if !regexp.MustCompile(`^(-l|--list)$`).MatchString(strings.TrimSpace(args)) {
						add("R2", "修改计划任务")
					}
				case "iptables", "nft", "ufw", "firewall-cmd":
					if !has(args, "--list", "--status", "-l", "status") {
						add("R2", "修改防火墙配置")
					}
				case "rm", "rmdir", "shred":
					for _, w := range words[1:] {
						p := filepath.Clean(w)
						if p == "/" || has(p, "/etc", "/var/lib", "/home", "/Users", "/var/www") || p == "~" || p == "$HOME" {
							add("R4", "删除重要文件或数据目录")
						}
					}
				case "mkfs", "mkfs.ext4", "mkfs.xfs":
					if !helpOnly(words[1:]) {
						add("R4", "格式化文件系统")
					}
				case "dd":
					if has(args, "of=/dev/") {
						add("R4", "覆盖磁盘设备")
					}
				case "hping3":
					if strings.Contains(args, "--flood") {
						add("R6", "发送洪泛流量")
					}
				}
				if has(exe, "mysql", "psql", "sqlite", "sqlcmd") {
					if regexp.MustCompile(`(?i)\b(drop\s+(table|database)|truncate\s+(table\s+)?\w+)`).MatchString(cmd) {
						add("R4", "删除数据库对象")
					}
					if regexp.MustCompile(`(?i)\bdelete\s+from\s+\w+\s*(;|"|'|$)`).MatchString(cmd) {
						add("R4", "全表删除数据")
					}
					if regexp.MustCompile(`(?i)\b(create|alter|drop)\s+(user|role)\b|\b(grant|revoke)\b`).MatchString(cmd) {
						add("R3", "修改数据库账号权限")
					}
				}
				return true
			})
		}
	}
	if has(name, "sql", "database", "query") {
		if regexp.MustCompile(`(?i)\b(drop\s+(table|database)|truncate\s+)`).MatchString(raw) {
			add("R4", "删除数据库对象")
		}
	}
	if hasExact(name, "read", "grep", "find", "ls", "glob") {
		add("A7", "读取或查询")
	}
	return hits, parseFailed
}
func protectedPath(p, platform string) bool {
	if platform == "windows" && unresolvedWindowsPath(p) {
		return true
	}
	p = policyPrefixPath(p, platform)
	library, system := "/Library/Launch", "/System/"
	if platform == "windows" {
		library, system = strings.ToLower(library), strings.ToLower(system)
		if p == "/windows" || strings.HasPrefix(p, "/windows/") {
			return true
		}
	}
	return p == "/etc" || strings.HasPrefix(p, "/etc/") || strings.HasPrefix(p, "/private/etc/") || strings.HasPrefix(p, library) || strings.HasPrefix(p, system)
}

// Normalize using the target's path grammar. POSIX backslashes are literal:
// slash replacement is comparison-only and must never be followed by cleaning.
func policyPrefixPath(p, platform string) string {
	if platform != "windows" {
		if runtime.GOOS == "windows" {
			p = path.Clean(p) // Remote POSIX path on a Windows server.
		} else {
			p = filepath.Clean(p)
		}
		return strings.ReplaceAll(p, "\\", "/")
	}
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, windowsVolume(p))
	return strings.ToLower(path.Clean(p))
}
func Evaluate(in ReviewInput, rules []Rule) *Decision { return evaluateAt(in, rules, "") }

// Legacy records have no matcher/target fields; preserve their original semantics.
func normalizeRule(r Rule) Rule {
	if r.Matcher == "" {
		if r.Builtin {
			r.Matcher = "semantic"
		} else {
			r.Matcher = "regex"
		}
	}
	if r.Target == "" {
		r.Target = "arguments"
	}
	if r.Matcher == "prompt-attack" {
		r.Categories = []string{"category::prompt-attack"}
	}
	if hasExact(r.Matcher, "btpii", "secret") {
		r.Categories = []string{SensitiveInfoCategory}
	}
	r.Semantics = nil
	if r.Builtin && hasExact(r.Matcher, "semantic", "btpii") {
		id := r.ID
		if r.SourceRuleID != "" {
			id = r.SourceRuleID
		}
		r.Semantics = builtinSemantics(id)
	}
	if r.Builtin && r.Matcher == "prompt-attack" {
		r.Semantics = &RuleSemantics{Summary: "Server-side prompt-attack tag detection", Checks: []string{"Pinned terminal patterns, tag classifier, optional NSFA evidence"}, Limits: "Opt-in; classifier labels never authorize a tool. Offline cached rules cannot evaluate this matcher."}
	}
	if entity := secretRulePattern(r); entity != "" {
		// OWASP LLM06 (2023–24), How to Prevent #1–2: sanitize both sides
		// of the model boundary. S3 stored alerts must not downgrade a deny.
		// https://genai.owasp.org/llmrisk2023-24/llm06-sensitive-information-disclosure/
		r.Decision = "reject"
		r.Semantics = &RuleSemantics{Summary: "Credential pattern detection: " + entity, Checks: []string{"Frozen Gitleaks regex, capture, entropy and content allowlists; argument keys and values"}, Limits: "Pattern detected does not mean verified active. No network verification or content rewriting; positive credential examples are deliberately omitted."}
	}
	return r
}
func sortRules(rules []Rule) {
	sort.SliceStable(rules, func(i, j int) bool {
		rank := map[string]int{"reject": 0, "alert": 1, "redact": 1, "approve": 2}
		if rank[rules[i].Decision] != rank[rules[j].Decision] {
			return rank[rules[i].Decision] < rank[rules[j].Decision]
		}
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority > rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})
}

func evaluateAt(in ReviewInput, rules []Rule, cwd string) *Decision {
	return evaluatePaths(in, rules, cwd, policyPath, runtime.GOOS)
}
func evaluatePaths(in ReviewInput, rules []Rule, cwd string, resolve func(string, string) string, platform string) *Decision {
	return evaluatePathsSensitive(in, rules, cwd, resolve, platform, secretSensitiveResult(context.Background(), in, rules))
}

// Submit supplies its one original-input scan to both verdict and privacy paths.
func evaluatePathsSensitive(in ReviewInput, rules []Rule, cwd string, resolve func(string, string) string, platform string, secretResult *SensitiveResult) *Decision {
	// Collect every semantic hit: disabling one rule must not hide another operation.
	hits, parseFailed := builtinMatchesPaths(in, cwd, resolve, platform)
	detailed, detailedParseFailed := detailedBuiltinMatches(in, cwd, resolve, platform)
	for id, what := range detailed {
		hits[id] = what
	}
	var unavailable *Decision
	if parseFailed || detailedParseFailed {
		// Like E_BTPII, an operational failure is not a dangerous-command finding.
		unavailable = &Decision{Decision: "reject", RuleID: "E_SHELL_PARSE", Comment: "Shell command could not be statically parsed."}
	}
	if secretResult != nil && secretResult.Unavailable {
		unavailable = &Decision{Decision: "reject", RuleID: "E_SECRET_SCAN", Comment: "Credential pattern scan unavailable."}
	}
	ordered := append([]Rule(nil), rules...)
	for i := range ordered {
		ordered[i] = normalizeRule(ordered[i])
	}
	sortRules(ordered)
	for _, r := range ordered {
		if !r.Enabled || (r.Tool != "" && r.Tool != in.ToolName) {
			continue
		}
		matched, what := false, in.ToolName
		if r.Matcher == "semantic" {
			id := r.ID
			if r.SourceRuleID != "" {
				id = r.SourceRuleID
			}
			what, matched = hits[id]
		} else if secretRulePattern(r) != "" {
			if secretResult != nil {
				for _, finding := range secretResult.Findings {
					matched = matched || finding.RuleID == r.ID
				}
			}
		} else {
			matched = matchesCustomRule(in, r)
		}
		if !matched {
			continue
		}
		// Rules are deny-first: preserve their deny, but never approve a failed parse.
		if unavailable != nil && r.Decision != "reject" {
			return unavailable
		}
		if secretResult != nil {
			// Source findings (including unavailable scans) govern omission.
			// Re-matching formatted comments can lose upstream token delimiters.
			return &Decision{Decision: r.Decision, RuleID: r.ID, Comment: "Review content omitted by sensitive-info policy."}
		}
		consequence := "按配置规则裁决该调用"
		if r.Matcher == "semantic" {
			consequence = "可能改变目标系统状态"
			if r.ID == "A7" {
				consequence = "返回查询结果"
			}
		}
		comment := "实际操作：" + what + "；成功后的后果：" + consequence + "；命中规则：" + r.ID + "（" + r.Name + "）"
		if r.Message != "" {
			comment += "；" + r.Message
		}
		decision := r.Decision
		if decision == "redact" {
			decision = "alert"
		} // No synchronous input rewrite: detection only.
		return &Decision{Decision: decision, RuleID: r.ID, Comment: RedactText(comment)}
	}
	return unavailable
}

// Share field/target/tool semantics between verdict selection and independent
// sensitive findings; a stronger winner must not hide a log-only match.
func matchesCustomRule(in ReviewInput, r Rule) bool {
	if !r.Enabled || r.Tool != "" && r.Tool != in.ToolName {
		return false
	}
	v := any(in.Arguments)
	if r.Target == "toolName" {
		v = in.ToolName
	} else if r.Field != "" {
		v = valueAt(in.Arguments, r.Field)
		if v == nil {
			return false
		}
	}
	switch r.Matcher {
	case "keywords":
		spans, err := customSensitiveSpans(r, stringValue(v))
		return err == nil && len(spans) > 0
	case "contains":
		return strings.Contains(stringValue(v), r.Pattern)
	case "regex":
		re, err := regexp.Compile(r.Pattern)
		return err == nil && re.MatchString(stringValue(v))
	}
	return false
}

func hasExact(s string, ss ...string) bool {
	for _, x := range ss {
		if s == x {
			return true
		}
	}
	return false
}
func (e *Engine) SaveRule(ctx context.Context, r Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Compiled template provenance is server-owned, never a rule CRUD input.
	r.SourceRuleID, r.TemplateID, r.TemplateRevision = "", "", 0
	// Builtin is provenance, not an immutable decision or a client-controlled flag.
	known := false
	for _, preset := range BuiltinRules() {
		if preset.ID == r.ID {
			known = true
			break
		}
	}
	if !known && !regexp.MustCompile(`^U_[A-Za-z0-9_-]{1,64}$`).MatchString(r.ID) {
		return errors.New("无效规则编号；新规则编号须以 U_ 开头")
	}
	if !known && r.Builtin {
		return errors.New("自定义规则不能标记为内置规则")
	}
	if r.Severity != "" && !hasExact(r.Severity, "unknown", "low", "medium", "high", "critical") {
		return errors.New("invalid risk severity")
	}
	for _, category := range r.Categories {
		if !validRiskCategory(category) {
			return errors.New("invalid protection category")
		}
	}
	r.Builtin = known
	r = normalizeRule(r)
	if !hasExact(r.Decision, "approve", "reject", "alert", "redact") || (r.Decision == "redact" && !hasExact(SensitiveInfoCategory, r.Categories...)) {
		return errors.New("无效裁决")
	}
	if len(r.Pattern) > 2048 || strings.TrimSpace(r.Name) == "" || len(r.Name) > 200 || len(r.Message) > 4000 {
		return errors.New("规则名称、表达式或消息无效")
	}
	if !hasExact(r.Target, "arguments", "toolName") {
		return errors.New("无效匹配对象")
	}
	switch r.Matcher {
	case "secret":
		if !known || r.Target != "arguments" || r.Field != "" || secretRulePattern(r) == "" || r.Pattern != secretRulePattern(r) {
			return errors.New("invalid secret rule")
		}
	case "prompt-attack":
		valid := false
		for _, tag := range promptAttackTags {
			valid = valid || r.Pattern == tag.slug
		}
		if !known || !valid || r.Target != "arguments" || r.Field != "" {
			return errors.New("invalid prompt-attack rule")
		}
	case "btpii":
		if !known || r.Target != "arguments" || r.Field != "" || !hasExact(r.Pattern, "bank-card", "id-number", "email", "mobile", "other") {
			return errors.New("invalid BTPII rule")
		}
	case "keywords":
		if !hasExact(SensitiveInfoCategory, r.Categories...) || strings.TrimSpace(r.Pattern) == "" {
			return errors.New("invalid sensitive-info keyword list")
		}
	case "semantic":
		if !known {
			return errors.New("语义识别仅适用于内置规则")
		}
		if r.Target != "arguments" || r.Field != "" || r.Pattern != "" {
			return errors.New("语义识别不使用参数路径或表达式，请切换匹配方式")
		}
	case "regex":
		if r.Pattern == "" {
			return errors.New("请填写匹配表达式")
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return errors.New("正则表达式无效")
		}
	case "contains":
		if r.Pattern == "" {
			return errors.New("请填写匹配文本")
		}
	default:
		return errors.New("无效匹配方式")
	}
	detail := r.Name
	if hasExact(SensitiveInfoCategory, r.Categories...) || hasExact(r.Matcher, "btpii", "keywords") {
		detail = fmt.Sprintf("id=%s action=%s matcher=%s category=%s enabled=%t", r.ID, r.Decision, r.Matcher, strings.Join(r.Categories, ","), r.Enabled)
	}
	return e.change(ctx, "rules", r.ID, r, "rule.save", detail)
}
func (e *Engine) DeleteRule(ctx context.Context, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !strings.HasPrefix(id, "U_") {
		return errors.New("内置规则请使用停用，或编辑后恢复默认")
	}
	return e.change(ctx, "rules", id, nil, "rule.delete", id)
}
func (e *Engine) SaveScope(ctx context.Context, s Scope) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s.ID == "" {
		s.ID = ID()
	}
	if err := e.validateRuleBinding(s); err != nil {
		return err
	}
	if s.NodeID != "" {
		if !hasExact(s.Platform, "linux", "darwin", "windows") || !agentPathAbs(s.Project, s.Platform) {
			return errors.New("远程授权范围须填写节点平台和绝对项目路径")
		}
	} else if !filepath.IsAbs(s.Project) {
		return errors.New("请填写绝对项目路径")
	}
	if s.Name == "" {
		return errors.New("请填写名称及绝对项目路径")
	}
	if s.NodeID == "" {
		p, err := filepath.EvalSymlinks(s.Project)
		if err != nil {
			return errors.New("项目路径不存在")
		}
		s.Project = p
	}
	for _, p := range s.Paths {
		if (s.NodeID == "" && !filepath.IsAbs(p)) || (s.NodeID != "" && !agentPathAbs(p, s.Platform)) {
			return errors.New("允许路径须为绝对路径")
		}
	}
	for _, t := range s.Targets {
		if t == "" || strings.ContainsAny(t, "/ :") {
			return errors.New("目标须为精确主机名或 IP，不含协议和端口")
		}
	}
	return e.change(ctx, "scopes", s.ID, s, "scope.save", s.Name)
}
func (e *Engine) DeleteScope(ctx context.Context, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.change(ctx, "scopes", id, nil, "scope.delete", id)
}
func within(root, p string) bool {
	r, err := filepath.Rel(root, p)
	return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
}
func checkScope(in ReviewInput, cwd string, scopes []Scope) *Decision {
	return checkScopePaths(in, cwd, scopes, policyPath, within)
}
func checkScopePaths(in ReviewInput, cwd string, scopes []Scope, resolve func(string, string) string, contains func(string, string) bool) *Decision {
	for _, s := range scopes {
		if !contains(s.Project, cwd) {
			continue
		}
		if hasExact(strings.ToLower(in.ToolName), "read", "write", "edit", "ls", "find", "grep", "glob") && len(s.Paths) > 0 {
			if p := argumentText(in.Arguments, "path", "file_path", "filePath"); p != "" {
				p = resolve(p, cwd)
				okPath := false
				for _, root := range s.Paths {
					if contains(resolve(root, cwd), p) {
						okPath = true
					}
				}
				if !okPath {
					return reject("SCOPE_PATH", "访问已配置授权范围之外的路径")
				}
			}
		}
		if len(s.Targets) > 0 {
			for _, field := range []string{"url", "host", "target"} {
				if v, ok := in.Arguments[field].(string); ok {
					host := v
					if u, err := url.Parse(v); err == nil && u.Host != "" {
						host = u.Hostname()
					}
					if !hasExact(strings.ToLower(host), s.Targets...) {
						return reject("SCOPE_TARGET", "访问已配置授权范围之外的目标")
					}
				}
			}
		}
	}
	return nil
}

// Resolve existing parent symlinks too, so a new file under a symlink is checked against its real destination.
func policyPath(p, cwd string) string {
	if p == "" {
		return ""
	}
	if filepath.Separator == '\\' {
		if unresolvedWindowsPath(p) {
			return p // The matcher denies unresolved forms, even without a scope.
		}
		p = windowsRootedPath(p, cwd)
	}
	if !filepath.IsAbs(p) {
		if cwd == "" {
			return filepath.Clean(p)
		}
		p = filepath.Join(cwd, p)
	}
	suffix := []string{}
	cur := filepath.Clean(p)
	for {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			parts := []string{real}
			for i := len(suffix) - 1; i >= 0; i-- {
				parts = append(parts, suffix[i])
			}
			return filepath.Join(parts...)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return filepath.Clean(p)
		}
		suffix = append(suffix, filepath.Base(cur))
		cur = parent
	}
}
func literalWord(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var out strings.Builder
	var part func(syntax.WordPart) bool
	part = func(p syntax.WordPart) bool {
		switch x := p.(type) {
		case *syntax.Lit:
			out.WriteString(x.Value)
			return true
		case *syntax.SglQuoted:
			out.WriteString(x.Value)
			return true
		case *syntax.DblQuoted:
			for _, p := range x.Parts {
				if !part(p) {
					return false
				}
			}
			return true
		default:
			return false
		}
	}
	for _, p := range w.Parts {
		if !part(p) {
			return ""
		}
	}
	return out.String()
}

func argumentText(args map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := args[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
