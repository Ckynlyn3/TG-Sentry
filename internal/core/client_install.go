package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"aegishook/internal/localaddr"
)

// ClientOptions installs files only. It never opens the server DB or starts a listener.
type ClientOptions struct {
	Dir, Binary, Agent, Scope, Project, PiDir, Endpoint, Token string
	EnrollmentCode                                             string
	BundlePublicKey                                            []byte
	Progress                                                   io.Writer
	Switch                                                     bool
	Resources                                                  map[string][]byte
}
type clientEntry struct {
	Installation
	CreatedFile bool     `json:"createdFile"`
	CreatedDirs []string `json:"createdDirs,omitempty"`
}
type clientManifest struct {
	Format    int               `json:"format"`
	NodeID    string            `json:"nodeId"`
	Entries   []clientEntry     `json:"entries"`
	Resources map[string]string `json:"resources"`
}
type ClientResult struct {
	Action    string   `json:"action"`
	Agent     string   `json:"agent"`
	Scope     string   `json:"scope"`
	Entry     string   `json:"entry,omitempty"`
	Remaining int      `json:"remaining"`
	Retained  []string `json:"retained,omitempty"`
	Warning   string   `json:"warning,omitempty"`
}
type clientEdit struct {
	root             *os.Root // Repair binds relative paths to the validated target handle.
	path             string
	before, after    []byte
	mode             os.FileMode
	oldLink, newLink string
	existed          bool
}

func ClientOperation(action string, o ClientOptions) (result ClientResult, err error) {
	result = ClientResult{Action: action, Agent: o.Agent, Scope: o.Scope}
	if action != "install" && action != "uninstall" {
		return result, errors.New("客户端只支持 install / uninstall")
	}
	if AgentName(o.Agent) == "" || (o.Scope != "global" && o.Scope != "project" && !(o.Agent == "cursor" && o.Scope == "enterprise")) {
		return result, errors.New("请选择有效的 Agent 和 global/project 范围")
	}
	if o.Scope == "enterprise" && o.Switch {
		return result, errors.New("Cursor enterprise staging cannot use --switch; deploy managed hooks before explicitly retiring active hooks")
	}
	if !filepath.IsAbs(o.Dir) {
		return result, errors.New("客户端目录必须是绝对路径")
	}
	o.Dir = filepath.Clean(o.Dir)
	if o.Dir == filepath.VolumeName(o.Dir)+string(filepath.Separator) {
		return result, errors.New("客户端目录不能是文件系统根目录")
	}
	if _, e := os.Stat(filepath.Join(o.Dir, "aegishook.db")); e == nil {
		return result, errors.New("客户端目录不能使用服务端数据目录")
	}
	if o.Scope == "project" {
		if !filepath.IsAbs(o.Project) {
			return result, errors.New("项目须使用绝对路径")
		}
		original := filepath.Clean(o.Project)
		o.Project, err = filepath.EvalSymlinks(original)
		if err != nil {
			if action != "uninstall" || !os.IsNotExist(err) {
				return result, errors.New("项目目录不存在")
			}
			o.Project = canonicalMissingPath(original)
		}
		st, e := os.Stat(o.Project)
		if !(action == "uninstall" && os.IsNotExist(e)) && (e != nil || !st.IsDir()) {
			return result, errors.New("项目须为目录")
		}
	} else if o.Project != "" {
		return result, errors.New("global 范围不能同时指定项目")
	}
	if action == "install" {
		o.Endpoint, err = localaddr.Endpoint(o.Endpoint)
		if err != nil {
			return result, err
		}
		if !filepath.IsAbs(o.Binary) {
			return result, errors.New("Hook 程序须为绝对路径")
		}
	}
	manifestPath := filepath.Join(o.Dir, "client.json")
	if action == "uninstall" {
		if _, e := os.Stat(o.Dir); os.IsNotExist(e) {
			return result, nil
		}
	}
	if err = os.MkdirAll(o.Dir, 0700); err != nil {
		return result, err
	}
	real, e := filepath.EvalSymlinks(o.Dir)
	if e != nil {
		return result, e
	}
	o.Dir = real
	manifestPath = filepath.Join(o.Dir, "client.json")
	lock, err := os.OpenFile(filepath.Join(o.Dir, "client.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return result, err
	}
	defer lock.Close()
	if err = lockProcessFile(lock); err != nil {
		return result, errors.New("另一个客户端安装/卸载正在进行")
	}
	// Keep the lock inode stable across operations; unlinking a held lock enables races.
	m := clientManifest{Format: 1, NodeID: ID(), Resources: map[string]string{}}
	if b, e := os.ReadFile(manifestPath); e == nil {
		if json.Unmarshal(b, &m) != nil || m.Format != 1 || len(m.NodeID) != 32 {
			return result, errors.New("客户端安装记录无效，未修改 Hook")
		}
	} else if !os.IsNotExist(e) {
		return result, e
	}
	if m.Resources == nil {
		m.Resources = map[string]string{}
	}
	if action == "install" {
		if err = prepareClientConnection(&o, &m); err != nil {
			return result, err
		}
		if strings.TrimSpace(o.Token) == "" || strings.ContainsAny(o.Token, "\r\n") {
			return result, errors.New("设备凭据为空或格式无效")
		}
		if o.Agent == "grok" && !o.Switch {
			for _, v := range m.Entries {
				if v.Agent == o.Agent && (v.Scope != o.Scope || v.Project != o.Project) {
					return result, errors.New("Grok 不支持多个安装范围，请使用 --switch 切换")
				}
			}
		}
	}
	current := -1
	for i, v := range m.Entries {
		if v.Agent == o.Agent && v.Scope == o.Scope && v.Project == o.Project {
			current = i
			break
		}
	}
	if action == "uninstall" && current < 0 {
		result.Remaining = len(m.Entries)
		if len(m.Entries) == 0 {
			result.Retained = removeClientPending(o.Dir)
		}
		return result, nil
	}
	target, err := clientTarget(o)
	if err != nil {
		return result, err
	}
	if current >= 0 {
		target = m.Entries[current]
	}
	result.Entry = target.Entry
	if o.Agent == "cursor" && o.Scope == "enterprise" {
		result.Warning = "Staged configuration only. Administrator/MDM must merge this file into " + CursorEnterprisePath(runtime.GOOS) + "; uninstall removes staging only, not the deployed system hook."
	}
	if action == "install" {
		// All scopes share one adapter and node identity, so client-side deduplication survives scope switches.
		if b, e := os.ReadFile(filepath.Join(o.Dir, "adapter", "connection.json")); e == nil && len(m.Entries) > 0 {
			var old struct{ Endpoint, Token string }
			if json.Unmarshal(b, &old) != nil || old.Endpoint != o.Endpoint || old.Token != o.Token {
				return result, errors.New("该客户端已连接其他地址或凭据；请先卸载其 Hook，再重新安装")
			}
		}
	}
	edits := []clientEdit{}
	next := []clientEntry{}
	removedDirs := []string{}
	for i, v := range m.Entries {
		remove := (action == "uninstall" && i == current) || (action == "install" && o.Switch && v.Agent == o.Agent && (v.Scope != o.Scope || (o.Agent == "grok" && v.Project != o.Project)))
		if remove {
			edit, e := clientHookEdit(v, false)
			if e != nil {
				return result, e
			}
			edits = append(edits, edit)
			removedDirs = append(removedDirs, v.CreatedDirs...)
		} else {
			next = append(next, v)
		}
	}
	if action == "install" {
		if o.Agent == "claude" && current < 0 {
			target.Installation, result.Warning = prepareClaudeHook(target.Installation)
		}
		if o.Agent == "codex" && current < 0 {
			target.Installation = prepareCodexHook(target.Installation)
		}
		edit, e := clientHookEdit(target, true)
		if e != nil {
			return result, e
		}
		if current < 0 {
			target.CreatedFile = !edit.existed
			target.CreatedDirs = missingParents(filepath.Dir(target.Entry))
			next = append(next, target)
		}
		edits = append(edits, edit)
		resourceData := map[string][]byte{}
		for _, name := range []string{"index.ts", "opencode.mjs"} {
			b, ok := o.Resources[name]
			if !ok {
				return result, fmt.Errorf("缺少适配器资源 %s", name)
			}
			resourceData[name] = b
		}
		// Issue #65 §3.4: enrollment is an immutable bootstrap, not live trust.
		connectionData, err := clientConnectionData(o, m.NodeID)
		if err != nil {
			return result, err
		}
		resourceData["connection.json"] = connectionData
		resourceData["runtime.json"] = mustJSON(map[string]string{"binary": o.Binary})
		for name, b := range resourceData {
			p := filepath.Join(o.Dir, "adapter", name)
			edit, e := clientRegularEdit(p, b)
			if e != nil {
				return result, e
			}
			if edit.existed && len(m.Entries) == 0 {
				return result, errors.New("客户端目录已有未登记的适配器文件，未覆盖")
			}
			if edit.existed && m.Resources[name] != digestBytes(edit.before) {
				return result, fmt.Errorf("适配器文件 %s 已被修改，未覆盖", name)
			}
			// Resource changes affect loaded agents; leave existing installations on their current runtime.
			if edit.existed && !bytes.Equal(edit.before, b) {
				return result, errors.New("已有适配器版本或程序路径不同；请先卸载全部客户端 Hook")
			}
			if name != "connection.json" || !edit.existed {
				edits = append([]clientEdit{edit}, edits...)
			}
			m.Resources[name] = digestBytes(b)
		}
	}
	m.Entries = next
	manifestData := mustJSON(m)
	if len(next) == 0 {
		manifestData = nil
	}
	manifestEdit, err := clientRegularEdit(manifestPath, manifestData)
	if err != nil {
		return result, err
	}
	edits = append(edits, manifestEdit)
	applied := []clientEdit{}
	createdDirs := []string{}
	for _, edit := range edits {
		createdDirs = append(createdDirs, missingParents(filepath.Dir(edit.path))...)
		if err = applyClientEdit(edit, false); err != nil {
			for j := len(applied) - 1; j >= 0; j-- {
				if e := applyClientEdit(applied[j], true); e != nil {
					err = fmt.Errorf("%w；回滚 %s 失败：%v", err, applied[j].path, e)
				}
			}
			removeEmptyDirs(createdDirs)
			return result, err
		}
		applied = append(applied, edit)
	}
	removeEmptyDirs(removedDirs)
	if action == "install" {
		_ = os.Remove(filepath.Join(o.Dir, "enrolled.json"))
	}
	if len(next) == 0 {
		if err := clientAdapterDirectoryError(o.Dir); err != nil {
			result.Retained = append(result.Retained, filepath.Join(o.Dir, "adapter"))
			result.Warning = err.Error()
			return result, nil
		}
		result.Retained = append(result.Retained, removeClientPolicyBundle(o.Dir, m.Resources["connection.json"])...)
		for name, hash := range m.Resources {
			if name != "index.ts" && name != "opencode.mjs" && name != "connection.json" && name != "runtime.json" {
				continue
			}
			p := filepath.Join(o.Dir, "adapter", name)
			b, e := os.ReadFile(p)
			if os.IsNotExist(e) {
				continue
			}
			if e != nil || digestBytes(b) != hash {
				result.Retained = append(result.Retained, p)
				continue
			}
			if e = os.Remove(p); e != nil {
				result.Retained = append(result.Retained, p)
			}
		}
		// Context caches contain local prompts and are owned by the command Hook.
		files, _ := filepath.Glob(filepath.Join(o.Dir, "adapter", "context-*.json"))
		for _, p := range files {
			base := filepath.Base(p)
			id := strings.TrimSuffix(strings.TrimPrefix(base, "context-"), ".json")
			if b, e := hex.DecodeString(id); e == nil && len(b) == 32 {
				if e = os.Remove(p); e != nil {
					result.Retained = append(result.Retained, p)
				}
			}
		}
		_ = os.Remove(filepath.Join(o.Dir, "adapter"))
	}
	result.Remaining = len(next)
	return result, nil
}

func clientTarget(o ClientOptions) (clientEntry, error) {
	base := agentHome(o.Agent)
	if o.Agent == "pi" && o.PiDir != "" {
		base = o.PiDir
	}
	if o.Scope == "project" {
		base = filepath.Join(o.Project, "."+o.Agent)
	}
	if !filepath.IsAbs(base) {
		return clientEntry{}, errors.New("Agent 配置目录须为绝对路径")
	}
	entry := filepath.Join(base, "hooks.json")
	if o.Agent == "cursor" && o.Scope == "enterprise" {
		entry = cursorStagingPath(o.Dir)
	}
	switch o.Agent {
	case "claude":
		entry = filepath.Join(base, "settings.json")
	case "grok":
		entry = filepath.Join(base, "hooks", "aegishook.json")
	case "opencode":
		entry = filepath.Join(base, "plugins", "aegishook.js")
	case "pi":
		entry = filepath.Join(base, "extensions", "aegishook.ts")
	}
	v := clientEntry{Installation: Installation{Agent: o.Agent, Scope: o.Scope, Project: o.Project, Entry: entry, ID: ID(), Installed: true, Version: Version, CreatedAt: time.Now()}}
	v.ManagedCommand = hookCommand(o.Binary, filepath.Join(o.Dir, "adapter", "connection.json"), o.Agent, runtime.GOOS)
	if o.Agent == "opencode" {
		v.ManagedContent = "// AegisHook managed entry\nexport { default } from " + string(mustJSON(fileURL(filepath.Join(o.Dir, "adapter", "opencode.mjs")))) + ";\n"
	}
	if o.Agent == "pi" {
		v.ManagedContent = filepath.Join(o.Dir, "adapter", "index.ts")
	}
	return v, nil
}
func clientHookEdit(v clientEntry, install bool) (clientEdit, error) {
	if v.Agent == "pi" {
		edit := clientEdit{path: v.Entry, mode: 0600}
		link, e := os.Readlink(v.Entry)
		if e == nil {
			if link != v.ManagedContent {
				return edit, errors.New("Pi 入口不是本客户端安装的符号链接")
			}
			edit.existed = true
			edit.oldLink = link
		} else if _, e = os.Lstat(v.Entry); !os.IsNotExist(e) {
			return edit, errors.New("Pi 同名入口已存在且不属于本客户端")
		}
		if install {
			edit.newLink = v.ManagedContent
		}
		return edit, nil
	}
	if v.Agent == "opencode" {
		var b []byte
		if install {
			b = []byte(v.ManagedContent)
		}
		edit, e := clientRegularEdit(v.Entry, b)
		if e == nil && edit.existed && string(edit.before) != v.ManagedContent {
			e = errors.New("OpenCode 插件已被修改或不属于本客户端")
		}
		return edit, e
	}
	next, old, mode, e := modifyHookDocument(v.Installation, install)
	if e != nil {
		return clientEdit{}, e
	}
	if !install && v.CreatedFile {
		var doc map[string]any
		if v.Agent == "cursor" && json.Unmarshal(next, &doc) == nil && len(doc) == 1 && doc["version"] == float64(1) {
			next = []byte("{}")
		}
		if strings.TrimSpace(string(next)) == "{}" {
			next = nil
		}
	}
	if !install && old == nil {
		next = nil
	}
	return clientEdit{path: v.Entry, before: old, after: next, mode: mode, existed: old != nil}, nil
}
func clientRegularEdit(p string, b []byte) (clientEdit, error) {
	edit := clientEdit{path: p, after: b, mode: 0600}
	st, e := os.Lstat(p)
	if os.IsNotExist(e) {
		return edit, nil
	}
	if e != nil {
		return edit, e
	}
	if !st.Mode().IsRegular() {
		return edit, fmt.Errorf("%s 不是普通文件，未覆盖", p)
	}
	edit.existed = true
	edit.mode = st.Mode().Perm()
	edit.before, e = os.ReadFile(p)
	return edit, e
}
func applyClientEdit(e clientEdit, undo bool) error {
	if e.root != nil {
		return applyConfinedClientEdit(e, undo)
	}
	expected, expectedLink, exists := e.before, e.oldLink, e.existed
	if undo {
		expected, expectedLink, exists = e.after, e.newLink, e.after != nil || e.newLink != ""
	}
	st, statErr := os.Lstat(e.path)
	if !exists {
		if !os.IsNotExist(statErr) {
			return fmt.Errorf("%s 在操作期间发生变化，未覆盖", e.path)
		}
	} else {
		if statErr != nil {
			return fmt.Errorf("%s 在操作期间消失，未覆盖", e.path)
		}
		if expectedLink != "" {
			link, err := os.Readlink(e.path)
			if err != nil || link != expectedLink {
				return fmt.Errorf("%s 链接发生变化，未覆盖", e.path)
			}
		} else {
			b, err := os.ReadFile(e.path)
			if !st.Mode().IsRegular() || err != nil || !bytes.Equal(b, expected) {
				return fmt.Errorf("%s 内容发生变化，未覆盖", e.path)
			}
		}
	}
	data, link := e.after, e.newLink
	if undo {
		data, link = e.before, e.oldLink
	}
	if data == nil && link == "" {
		err := os.Remove(e.path)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.path), 0700); err != nil {
		return err
	}
	if link != "" {
		if current, err := os.Readlink(e.path); err == nil && current == link {
			return nil
		}
		return os.Symlink(link, e.path)
	}
	return AtomicFile(e.path, data, e.mode)
}
func missingParents(p string) []string {
	out := []string{}
	for {
		if _, e := os.Stat(p); !os.IsNotExist(e) {
			return out
		}
		out = append(out, p)
		parent := filepath.Dir(p)
		if parent == p {
			return out
		}
		p = parent
	}
}
func removeEmptyDirs(dirs []string) {
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, p := range dirs {
		_ = os.Remove(p)
	}
}
func digestBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func canonicalMissingPath(p string) string {
	for parent := filepath.Dir(p); ; parent = filepath.Dir(parent) {
		if real, err := filepath.EvalSymlinks(parent); err == nil {
			relative, _ := filepath.Rel(parent, p)
			return filepath.Join(real, relative)
		}
		if filepath.Dir(parent) == parent {
			return p
		}
	}
}

// An interrupted first installation may have only a pending ticket or enrollment retry record.
func removeClientPending(dir string) []string {
	retained := []string{}
	for _, name := range []string{"request.json", "enrolled.json"} {
		p := filepath.Join(dir, name)
		b, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !clientPendingOwned(name, b) {
			retained = append(retained, p)
			continue
		}
		if err = os.Remove(p); err != nil {
			retained = append(retained, p)
		}
	}
	return retained
}

func clientPendingOwned(name string, data []byte) bool {
	if name == "request.json" {
		var request ClientRequestTicket
		return json.Unmarshal(data, &request) == nil && len(request.ID) == 32 && len(request.Secret) == 64
	}
	var conn ClientConnection
	return json.Unmarshal(data, &conn) == nil && len(conn.NodeID) == 32 && len(conn.Token) == 64
}

// Keep authenticated enrollment bytes through retry and install (§3.4). Existing
// connection bytes, including legacy snapshots, must not change with live trust.
func clientConnectionData(o ClientOptions, nodeID string) ([]byte, error) {
	for _, name := range []string{filepath.Join("adapter", "connection.json"), "enrolled.json"} {
		data, err := os.ReadFile(filepath.Join(o.Dir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var conn ClientConnection
		if err := json.Unmarshal(data, &conn); err != nil {
			return nil, fmt.Errorf("decode enrollment snapshot: %w", err)
		}
		if conn.BundleTrust != nil {
			if _, err := BootstrapPolicyTrust(conn.BundlePublicKey, conn.BundleTrust); err != nil {
				return nil, err
			}
		}
		return data, nil
	}
	// Internal/offline fixtures and legacy connections keep the pre-#65 bytes.
	return mustJSON(ClientConnection{Endpoint: o.Endpoint, Token: o.Token, NodeID: nodeID, BundlePublicKey: o.BundlePublicKey}), nil
}

// ponytail: pathname-based lock/edit helpers leave a TOCTOU window after Lstat;
// migrate them together to os.Root for traversal-resistant cleanup.
// https://go.dev/blog/osroot#introducing-osroot
func clientAdapterDirectoryError(dir string) error {
	path := filepath.Join(dir, "adapter")
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("adapter directory retained: %w", err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("%s is a symlink or not a directory; retained without cleanup", path)
	}
	return nil
}

// Plan §4 and lead D6 cleanup disposition: remove only re-provable local state.
// Keep both files on failed validation, and keep the lock inode stable (§3.5).
func removeClientPolicyState(dir, connectionHash string) []string {
	if clientAdapterDirectoryError(dir) != nil {
		return []string{filepath.Join(dir, "adapter")}
	}
	path := filepath.Join(dir, "adapter", "bundle.json")
	paths := []string{}
	for _, p := range []string{path, policyTrustPath(path)} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return nil
	}
	lock, err := lockPolicyCache(path)
	if err != nil {
		return paths
	}
	defer lock.Close()
	edits := []clientEdit{}
	for _, p := range paths {
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() || st.Size() > PolicyBundleMaxBytes {
			return paths
		}
		edit, err := clientRegularEdit(p, nil)
		if err != nil || len(edit.before) > PolicyBundleMaxBytes {
			return paths
		}
		edits = append(edits, edit)
	}
	if !clientPolicyStateOwned(path, connectionHash) {
		return paths
	}
	for i, edit := range edits {
		if err := applyClientEdit(edit, false); err != nil {
			// Keep trust when the bundle could not be removed; never strand it.
			return paths[i:]
		}
	}
	return nil
}

func clientPolicyStateOwned(path, connectionHash string) bool {
	data, err := os.ReadFile(filepath.Join(filepath.Dir(path), "connection.json"))
	var conn ClientConnection
	if err != nil || digestBytes(data) != connectionHash || json.Unmarshal(data, &conn) != nil {
		return false
	}
	bootstrap, err := BootstrapPolicyTrust(conn.BundlePublicKey, conn.BundleTrust)
	if err != nil {
		return false
	}
	state, err := ReadPolicyTrust(path, bootstrap)
	if err != nil {
		return false
	}
	// D6 discards intermediate roots. A compacted jump cannot be re-proved;
	// retaining and reporting it is §4's safe outcome, not a runtime trust reset.
	anchor, _, err := parseTrustState(bootstrap)
	if err != nil {
		return false
	}
	if state.Cache != nil && (!bytes.Equal(state.Cache.Payload, bootstrap.Current.Payload) || !clientTrustRecordOwned(*state.Cache, anchor)) {
		return false
	}
	if !clientTrustRecordOwned(state.Current, anchor) {
		return false
	}
	_, _, err = ReadPolicyBundleWithTrust(path, state, conn.NodeID)
	return err == nil || os.IsNotExist(err)
}

func clientTrustRecordOwned(signed SignedTrustRecord, anchor TrustRecord) bool {
	payload, err := TrustRecordBytes(anchor)
	if err != nil {
		return false
	}
	if bytes.Equal(signed.Payload, payload) {
		// Legacy v1 is synthesized from the installed pin without a signature.
		return (anchor.Version == 1 && len(signed.Signatures) == 0) || hasTrustSignature(signed, anchor)
	}
	_, err = VerifyTrustRecord(signed, anchor)
	return err == nil
}
