package discovery

// AgentPaths is the evidence/collector table, not an executable or vendor-version
// probe. Paths are slash-separated and relative to the acquired account home.
// S5 may supply own-home environment overrides; confinement is never relaxed.
type AgentPaths struct {
	Family      string
	Supported   bool
	ConfigFiles []string
	VendorDir   string
	TGTargets   []string
	SkillsDir   string
	MemoryFiles []string
	PluginsDir  string
}

// PathsForFamily returns fresh data from plan §3.3. Config evidence comes from
// ConfigFileProbe::probe_all (Pack A §1); TG-only entries mirror clientTarget in
// internal/core/client_install.go. No inferred paths or built-in tool catalogs.
func PathsForFamily(family string) (AgentPaths, bool) {
	p := AgentPaths{Family: family, Supported: true}
	switch family {
	case "claude":
		p.ConfigFiles = []string{".claude.json"}
		p.VendorDir = ".claude"
		p.TGTargets = []string{".claude/settings.json"}
		p.SkillsDir = ".claude/skills"
		p.MemoryFiles = []string{".claude/CLAUDE.md"}
	case "codex":
		p.ConfigFiles = []string{".codex/config.toml"}
		p.TGTargets = []string{".codex/hooks.json"}
		p.MemoryFiles = []string{".codex/AGENTS.md", ".codex/AGENTS.override.md"}
	case "cursor":
		p.ConfigFiles = []string{".cursor/cli-config.json", ".cursor/mcpServers.json"}
		p.TGTargets = []string{".cursor/hooks.json"}
	case "opencode":
		p.ConfigFiles = []string{".config/opencode/opencode.json", ".config/opencode/opencode.jsonc", ".config/opencode/config.json"}
		p.TGTargets = []string{".config/opencode/plugins/aegishook.js"}
		p.PluginsDir = ".config/opencode/plugins"
	case "pi":
		p.VendorDir = ".pi/agent"
		p.TGTargets = []string{".pi/agent/extensions/aegishook.ts"}
		p.PluginsDir = ".pi/agent/extensions"
	case "grok":
		p.VendorDir = ".grok"
		p.TGTargets = []string{".grok/hooks/aegishook.json"}
		p.PluginsDir = ".grok/hooks"
	case "gemini", "trae", "hermes", "openclaw":
		p.Supported = false
	default:
		return AgentPaths{}, false
	}
	return p, true
}
