package discovery

import (
	"context"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Policy is S5's minimal input; S6 owns the verified protection-state settings.
// Callers project those settings here rather than introducing a second policy.
type Policy struct {
	Enabled         bool
	IntervalSeconds int
}

// ScanEnvironment contains only caller-provided metadata, never credentials.
// Variables is a snapshot of the five allowlisted environment overrides in plan
// §3.3; all-local-account scans ignore it. LockPath belongs to the caller's
// private state root. OwnHome requires a provider returning exactly one account.
type ScanEnvironment struct {
	NodeID             string
	Scope              ReportScope
	CredentialsPresent bool
	LockPath           string
	Variables          map[string]string
}

type scanIO struct {
	lock     func(string) (*ScanLock, error)
	openHome func(string, string) (*HomeRoot, HomeState, Reason)
}

// Scan composes account enumeration, confined probes and metadata-only collectors.
// The credential/policy gate precedes ALL I/O, including locking and enumeration.
// A nil provider uses EnumerateLocalAccounts only for AllLocalAccounts. The own-
// home caller supplies its enrolled account; the library never reads credentials.
// Disabled calls return Report{}. Lock/enumeration failures and cancellation
// return Final=false: callers must not ingest those as completed full reports.
func Scan(ctx context.Context, policy Policy, accounts func(context.Context) ([]AccountHome, error), env ScanEnvironment) Report {
	return scan(ctx, policy, accounts, env, scanIO{TryScanLock, OpenHome})
}

func scan(ctx context.Context, policy Policy, accounts func(context.Context) ([]AccountHome, error), env ScanEnvironment, io scanIO) (report Report) {
	if !env.CredentialsPresent || !policy.Enabled || policy.IntervalSeconds <= 0 || ctx.Err() != nil {
		return Report{}
	}
	if env.Scope != OwnHome && env.Scope != AllLocalAccounts {
		return Report{}
	}
	report = Report{SchemaVersion: SchemaVersion, NodeID: env.NodeID, Scope: env.Scope,
		Mode: "full", ScanStartedAt: time.Now().UTC(), Accounts: []Account{}}
	defer func() { report.ScanCompletedAt = time.Now().UTC() }()
	lock, err := io.lock(env.LockPath)
	if err != nil {
		return report
	}
	defer func() {
		if lock.Close() != nil {
			report.Final = false
		}
	}()
	homes, err := scanHomes(ctx, accounts, env.Scope)
	if err != nil {
		return report
	}
	for _, home := range homes {
		report.Accounts = append(report.Accounts, scanAccount(ctx, home, env, io))
		if ctx.Err() != nil {
			return report
		}
	}
	report.Final = ctx.Err() == nil
	return report
}

func scanHomes(ctx context.Context, accounts func(context.Context) ([]AccountHome, error), scope ReportScope) ([]AccountHome, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if accounts == nil {
		if scope == OwnHome {
			return nil, ErrInvalidReport
		}
		accounts = EnumerateLocalAccounts
	}
	homes, err := accounts(ctx)
	if err != nil {
		return nil, err
	}
	homes, err = normalizeAccounts(homes)
	if err == nil && scope == OwnHome && len(homes) != 1 {
		return nil, ErrInvalidReport
	}
	return homes, err
}

func scanAccount(ctx context.Context, home AccountHome, env ScanEnvironment, io scanIO) Account {
	account := Account{ObservedLocalAccount: home.ObservedLocalAccount, AccountID: home.AccountID,
		HomePath: home.HomePath, HomeState: HomeUnavailable, Agents: []Agent{}}
	var root *HomeRoot
	var reason Reason
	if ctx.Err() != nil {
		reason = ReasonCanceled
	} else {
		// OpenHome acquires os.Root FIRST, then validates root.Stat(".") and UID
		// ownership (R1). No pathname stat, chdir, shell or vendor execution here.
		root, account.HomeState, reason = io.openHome(home.HomePath, home.AccountID)
	}
	if root != nil {
		defer root.Close()
	}
	for _, family := range []string{"claude", "codex", "cursor", "opencode", "pi", "grok", "gemini", "trae", "hermes", "openclaw"} {
		paths, _ := PathsForFamily(family)
		account.Agents = append(account.Agents, scanFamily(ctx, root, paths, home, env, reason))
	}
	return account
}

func scanFamily(ctx context.Context, root *HomeRoot, paths AgentPaths, home AccountHome, env ScanEnvironment, homeReason Reason) Agent {
	agent := Agent{Family: paths.Family, Found: FoundUnknown, Version: "unknown", Categories: probeCategories(paths)}
	reason := homeReason
	if ctx.Err() != nil {
		reason = ReasonCanceled
	}
	if reason == "" && env.Scope == OwnHome {
		paths, reason = ownHomePaths(paths, home.HomePath, env.Variables)
	}
	if reason == "" && root != nil {
		agent, reason = root.Probe(ctx, paths)
		if reason == "" {
			agent.Categories = root.Collect(ctx, paths, env.NodeID, home.AccountID)
		}
	}
	if ctx.Err() != nil {
		reason = ReasonCanceled
		agent.Found = FoundUnknown
	}
	if reason != "" {
		agent.Categories = failedHomeCategories(agent.Categories, reason)
	}
	return agent
}

func failedHomeCategories(categories []Category, reason Reason) []Category {
	result := append([]Category(nil), categories...)
	for i, c := range result {
		if c.Scope != ScopeHome || c.ScanState == ScanNotSupported {
			continue
		}
		result[i] = collectionFailure(c, reason)
		if reason == ReasonTGTargetOnly {
			result[i].ScanState = ScanUnknown
		}
	}
	return result
}

// Rebase only paths already in the evidence table, following agentHome in
// internal/core/agents.go and piAgentDir in install.go. In particular Claude's
// fixed .claude.json evidence is not a child of .claude and is not invented anew.
// Absolute overrides outside this account's os.Root cannot be scanned; fail the
// family closed rather than silently substituting defaults or opening a new root.
func ownHomePaths(paths AgentPaths, home string, env map[string]string) (AgentPaths, Reason) {
	prefix, override := ownHomeOverride(paths.Family, env)
	if override == "" {
		return paths, ""
	}
	rel, err := filepath.Rel(home, override)
	if err != nil || !filepath.IsAbs(override) {
		return paths, ReasonEscapedRoot
	}
	rel = filepath.ToSlash(rel)
	if rel != "." && !validSourcePath(rel) {
		return paths, ReasonEscapedRoot
	}
	rebase := func(value string) string {
		if value == prefix {
			return rel
		}
		if strings.HasPrefix(value, prefix+"/") {
			return path.Join(rel, strings.TrimPrefix(value, prefix+"/"))
		}
		return value
	}
	paths.ConfigFiles = rebasePaths(paths.ConfigFiles, rebase)
	paths.TGTargets = rebasePaths(paths.TGTargets, rebase)
	paths.MemoryFiles = rebasePaths(paths.MemoryFiles, rebase)
	paths.VendorDir, paths.SkillsDir, paths.PluginsDir = rebase(paths.VendorDir), rebase(paths.SkillsDir), rebase(paths.PluginsDir)
	return paths, ""
}

func ownHomeOverride(family string, env map[string]string) (prefix, override string) {
	switch family {
	case "claude":
		return ".claude", env["CLAUDE_CONFIG_DIR"]
	case "codex":
		return ".codex", env["CODEX_HOME"]
	case "opencode":
		if env["OPENCODE_CONFIG_DIR"] != "" {
			return ".config/opencode", env["OPENCODE_CONFIG_DIR"]
		}
		if env["XDG_CONFIG_HOME"] != "" {
			return ".config/opencode", filepath.Join(env["XDG_CONFIG_HOME"], "opencode")
		}
	case "pi":
		return ".pi/agent", env["PI_CODING_AGENT_DIR"]
	}
	return "", ""
}

func rebasePaths(paths []string, rebase func(string) string) []string {
	result := make([]string, len(paths))
	for i, value := range paths {
		result[i] = rebase(value)
	}
	return result
}
