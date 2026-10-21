package core

import (
	"net/url"
	"path"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Existing R_SYS_PATH policy roots; GNU rm --preserve-root explains the root
// guard. Home-wide deletion is local policy, not a GNU list of protected paths.
// Sources and the bounded Windows matcher contract are in docs/rules.md.
var systemRoots = []string{"/", "/etc", "/bin", "/usr", "/boot", "/var", "/lib", "/lib64", "/sys", "/proc", "/dev", "/sbin", "/root", "/home", "/Users", "/System", "/Library", "/private/etc", "/private/var"}
var homeDirectory = regexp.MustCompile(`^/(?:Users|home)/[^/]+$`)

func destructiveTarget(arg, cwd, platform string, resolve func(string, string) string) bool {
	if hasExact(strings.TrimRight(arg, "/"), "~", "~/*", "$HOME", "$HOME/*", "${HOME}", "${HOME}/*") {
		return true
	}
	resolved := resolve(arg, cwd)
	if platform == "windows" && unresolvedWindowsPath(resolved) {
		return true // Device and drive-relative forms fail closed (#62).
	}
	p := strings.ReplaceAll(resolved, "\\", "/")
	// Exempt only plain project-relative operands. Cleaning a symlink/.. or
	// expansion before this check cannot establish that cleanup stays local.
	if !path.IsAbs(arg) && !uncertainDeletionOperand(arg) && cwd != "" && cwd != "/" && cwd != "/root" && !homeDirectory.MatchString(path.Clean(cwd)) {
		// Compare in the same namespace (e.g. macOS /home resolves under /System).
		// Keep both lexical and resolved root/home guards; see docs/rules.md.
		resolvedCWD := cwd
		if platform != "windows" {
			resolvedCWD = resolve(".", cwd)
		} // Preserve the existing Windows containment semantics (#81).
		guardCWD := resolvedCWD
		// APFS firmlinks join System/Data hierarchies (Apple WWDC19 session 710).
		// /home's symlink and /usr/share/firmlinks expose this Data-volume spelling.
		// https://developer.apple.com/videos/play/wwdc2019/710/
		const dataVolume = "/System/Volumes/Data"
		if platform == "darwin" && (guardCWD == dataVolume || strings.HasPrefix(guardCWD, dataVolume+"/")) {
			guardCWD = strings.TrimPrefix(guardCWD, dataVolume)
		}
		if guardCWD != "" && !hasExact(guardCWD, systemRoots...) && !homeDirectory.MatchString(path.Clean(guardCWD)) && within(resolvedCWD, p) {
			return false
		}
	}
	if platform == "windows" {
		p = policyPrefixPath(resolved, platform)
		if p == "/windows" || strings.HasPrefix(p, "/windows/") {
			return true // Same Windows system root protectedPath uses.
		}
	}
	for _, root := range systemRoots {
		if platform == "windows" {
			root = strings.ToLower(root)
		}
		if p == root || (root != "/" && strings.HasPrefix(p, root+"/")) || (root == "/" && hasExact(p, "/*", "/.*")) {
			return true
		}
	}
	return false
}

// Preserve the imported conservative recursive-rm policy for operands whose
// traversal/expansion cannot be proven to be project-local without execution.
func uncertainDeletionOperand(arg string) bool {
	return strings.HasPrefix(arg, "~") || strings.ContainsAny(arg, "*?[]$") || containsArg(strings.Split(arg, "/"), "..")
}

// Recognize only the named HOME expansion, not arbitrary shell variables.
func riskWord(w *syntax.Word) string {
	if text := literalWord(w); text != "" {
		return text
	}
	var parts func([]syntax.WordPart) (string, bool)
	parts = func(words []syntax.WordPart) (string, bool) {
		var out strings.Builder
		for _, part := range words {
			switch x := part.(type) {
			case *syntax.Lit:
				out.WriteString(x.Value)
			case *syntax.DblQuoted:
				text, ok := parts(x.Parts)
				if !ok {
					return "", false
				}
				out.WriteString(text)
			case *syntax.ParamExp:
				if x.Param.Value != "HOME" || x.Excl || x.Length || x.Width || x.Index != nil || x.Slice != nil || x.Repl != nil || x.Exp != nil {
					return "", false
				}
				out.WriteString("$HOME")
			default:
				return "", false
			}
		}
		return out.String(), true
	}
	text, _ := parts(w.Parts)
	return text
}

func remoteShellPipe(pipe *syntax.BinaryCmd) bool {
	left, lok := pipe.X.Cmd.(*syntax.CallExpr)
	right, rok := pipe.Y.Cmd.(*syntax.CallExpr)
	if !lok || !rok {
		return false
	}
	download, execute := callWords(left), callWords(right)
	if len(download) == 0 || len(execute) == 0 || !hasExact(path.Base(execute[0]), "sh", "bash", "dash", "zsh") {
		return false
	}
	if !shellReadsPipe(execute[1:]) {
		return false
	}
	// Only replacing downloader stdout or interpreter stdin breaks this flow.
	// In particular, redirecting stderr to /dev/null leaves the pipe intact.
	for _, red := range pipe.X.Redirs {
		if (hasOutput(red.Op) || red.Op == syntax.DplOut) && (red.N == nil || red.N.Value == "1") {
			return false
		}
	}
	for _, red := range pipe.Y.Redirs {
		if !hasOutput(red.Op) && red.Op != syntax.DplOut && (red.N == nil || red.N.Value == "0") {
			return false
		}
	}
	exe, args := path.Base(download[0]), download[1:]
	if !hasExact(exe, "curl", "wget") || helpOnly(args) {
		return false
	}
	method, addresses := httpCommand(exe, args)
	if method == "HEAD" || len(addresses) == 0 {
		return false
	}
	output := optionValue(args, "-o", "--output")
	if exe == "wget" {
		output = optionValue(args, "-O", "--output-document")
		// GNU wget short options may be combined, e.g. -qO- or -qO file.
		for i, arg := range args {
			if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") {
				continue
			}
			if at := strings.IndexByte(arg, 'O'); at > 0 {
				output = arg[at+1:]
				if output == "" && i+1 < len(args) {
					output = args[i+1]
				}
			}
		}
	}
	if (exe == "wget" && output != "-") || (exe == "curl" && (output != "" && output != "-" || containsArg(args, "-O", "--remote-name", "-I", "--head"))) {
		return false
	}
	for _, address := range addresses {
		if isDownloadURL(address) {
			return true
		}
	}
	return false
}

func shellReadsPipe(args []string) bool {
	stdin := false
	for i, arg := range args {
		if arg == "--" {
			return stdin || i == len(args)-1
		}
		if strings.HasPrefix(arg, "-") {
			if helpOnly([]string{arg}) || (strings.HasPrefix(arg, "--") && arg == "--command") || (!strings.HasPrefix(arg, "--") && strings.Contains(arg, "c")) {
				return false
			}
			stdin = stdin || (!strings.HasPrefix(arg, "--") && strings.Contains(arg, "s"))
		} else if !stdin {
			return false // A script filename replaces stdin as the source of code.
		}
	}
	return true
}

func isDownloadURL(address string) bool {
	u, err := url.Parse(address)
	return err == nil && u.Host != "" && hasExact(u.Scheme, "http", "https")
}

// go.mod has mvdan.cc/sh (POSIX/Bash), no PowerShell parser. Keep Windows
// matching lexical: preserve backslashes, quoted arguments and command boundaries.
// ponytail: no alias resolution, encoded commands or cross-statement data flow;
// a native PowerShell AST adapter is the upgrade path if that coverage is needed.
var windowsToken = regexp.MustCompile(`(?s:<#.*?#>)|#[^\r\n]*|"(?:` + "`" + `.|""|[^"])*"|'(?:''|[^'])*'|[;|&()\r\n]|[^\s;|&()'"#]+`)

func windowsText(token string) string {
	if len(token) >= 2 && (token[0] == '\'' || token[0] == '"') {
		return token[1 : len(token)-1]
	}
	return token
}
func windowsName(token string) string {
	return strings.TrimSuffix(strings.ToLower(path.Base(strings.ReplaceAll(windowsText(token), "\\", "/"))), ".exe")
}

// Argument tokens of a Windows segment with surrounding quotes removed, so a
// quoted "/add" or subcommand compares like the POSIX callWords slice.
func windowsArgs(tokens []string) []string {
	args := make([]string, 0, len(tokens))
	for _, token := range tokens {
		args = append(args, windowsText(token))
	}
	return args
}
func windowsRiskPath(token string) bool {
	p := strings.ToLower(strings.ReplaceAll(windowsText(token), "\\", "/"))
	p = strings.TrimPrefix(p, "//?/") // Win32 extended-length path prefix.
	// Symbolic roots only: do not read the review server's environment. Names:
	// https://learn.microsoft.com/en-us/windows/deployment/usmt/usmt-recognized-environment-variables
	for _, variable := range []string{"systemroot", "windir", "programfiles", "programfiles(x86)", "programw6432"} {
		for _, root := range []string{"%" + variable + "%", "$env:" + variable} {
			if p == root || strings.HasPrefix(p, root+"/") {
				return true
			}
		}
	}
	for _, root := range []string{"%systemdrive%", "$env:systemdrive"} {
		if strings.HasPrefix(p, root) {
			p = "x:" + strings.TrimPrefix(p, root) // Preserve drive-path shape, not a host drive value.
			break
		}
	}
	if hasExact(strings.TrimRight(p, "/"), "~", "~/*", "$home", "$home/*", "$env:userprofile", "$env:userprofile/*", "%userprofile%", "%userprofile%/*", "%systemroot%", "$env:systemroot") {
		return true
	}
	if len(p) < 3 || p[1:3] != ":/" {
		return false
	}
	p = path.Clean(p[2:])
	return hasExact(p, "/", "/*", "/*.*", "/windows") || strings.HasPrefix(p, "/windows/")
}

// Index each delimiter-bounded segment once instead of rescanning every suffix
// after a parenthesis. Rightmost positions answer the original suffix predicates
// in constant time; parser nesting retains the existing depth ceiling above.
type windowsSegmentIndex struct {
	whatIf, outfile, url, risk, remote int
}

func indexWindowsSegment(tokens, lower []string) windowsSegmentIndex {
	index := windowsSegmentIndex{-1, -1, -1, -1, -1}
	for i, token := range tokens {
		if token == "(" || token == ")" {
			continue // Neither delimiter is an option, URL or risky path.
		}
		if hasExact(lower[i], "-whatif", "-wi", "/?") {
			index.whatIf = i
		}
		if hasExact(lower[i], "-outfile", "-o") {
			index.outfile = i
		}
		if isDownloadURL(windowsText(strings.TrimRight(token, ")"))) {
			index.url = i
		}
		if windowsRiskPath(token) {
			index.risk = i
		}
	}
	for i, token := range tokens {
		if token != "(" {
			continue
		}
		if i+1 < len(tokens) && index.url > i+1 && index.outfile <= i+1 && hasExact(windowsName(tokens[i+1]), "iwr", "irm", "invoke-webrequest", "invoke-restmethod") {
			index.remote = i
		}
	}
	return index
}

func windowsWebClientExpression(args []string) bool {
	return len(args) > 6 && args[0] == "(" && strings.EqualFold(args[1], "New-Object") && hasExact(strings.ToLower(args[2]), "net.webclient", "system.net.webclient") && args[3] == ")" && strings.EqualFold(args[4], ".DownloadString") && args[5] == "(" && isDownloadURL(windowsText(args[6]))
}

func inspectWindows(command string, depth int, add func(string)) {
	if depth > 3 {
		return
	} // Existing shell nesting ceiling, not an input cap.
	tokens := windowsToken.FindAllString(command, -1)
	lower := make([]string, len(tokens))
	for i, token := range tokens {
		lower[i] = strings.ToLower(token)
	}
	for start := 0; start < len(tokens); {
		end := start + 1
		for end < len(tokens) && !hasExact(tokens[end], ";", "|", "&", "\n", "\r") {
			end++
		}
		index := indexWindowsSegment(tokens[start:end], lower[start:end])
		// Classify the downstream pipe target once per segment; per-candidate normalization is quadratic.
		pipeToIEX := end+1 < len(tokens) && tokens[end] == "|" && hasExact(windowsName(tokens[end+1]), "iex", "invoke-expression")
		for i := start; i < end; i++ {
			if i != 0 && !hasExact(tokens[i-1], ";", "|", "&", "\n", "\r", "(") {
				continue
			}
			if tokens[i] == "(" || tokens[i] == ")" {
				continue // No original executable-name branch accepts a delimiter.
			}
			if strings.HasPrefix(tokens[i], "#") || strings.HasPrefix(tokens[i], "<#") {
				continue
			}
			if (tokens[i][0] == '\'' || tokens[i][0] == '"') && (i == 0 || tokens[i-1] != "&") {
				continue
			}
			exe := windowsName(tokens[i])
			if hasExact(exe, "rem", "echo", "write-output") {
				break
			}
			if hasExact(exe, "powershell", "pwsh", "cmd") {
				for j := i + 1; j+1 < end; j++ {
					if hasExact(lower[j], "-command", "-c", "/c", "/k") {
						inspectWindows(strings.Join(append([]string{windowsText(tokens[j+1])}, tokens[j+2:end]...), " "), depth+1, add)
						break
					}
				}
				break
			}
			if hasExact(exe, "format-volume", "clear-disk") {
				add("R_HIGH_RISK_DESTRUCTION")
			}
			if hasExact(exe, "shutdown", "reboot", "halt", "poweroff", "stop-computer", "restart-computer") && !usageOnly(windowsArgs(tokens[i+1:end])) {
				add("R_SYS_SHUTDOWN")
			}
			if hasExact(exe, "net", "net1") && netAccountMutation(windowsArgs(tokens[i+1:end])) {
				add("R3")
			}
			if hasExact(exe, "remove-item", "ri", "rm", "rmdir", "del", "erase", "rd") && index.whatIf <= i-start && index.risk > i-start {
				add("R_HIGH_RISK_DESTRUCTION")
			}
			if hasExact(exe, "iex", "invoke-expression") && (index.remote > i-start || windowsWebClientExpression(tokens[i+1:end])) {
				add("R_HIGH_RISK_REMOTE_EXEC")
			}
			if pipeToIEX && hasExact(exe, "iwr", "irm", "invoke-webrequest", "invoke-restmethod") && index.outfile <= i-start && index.url > i-start {
				add("R_HIGH_RISK_REMOTE_EXEC")
			}
		}
		start = end
	}
}
