package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// Named local resource budget: #38/41 approved plan §11 R7's 2 MiB config
// parse cap, also used by internal/server/server.go's request reader.
const clientDriftMaxBytes = 2 << 20

var errDriftOversize = errors.New("drift file exceeds config parse budget")

// ManifestOutcome is the internal A3 outcome; absent is not invalid/unreadable.
type ManifestOutcome string

const (
	ManifestAbsent     ManifestOutcome = "absent"
	ManifestInvalid    ManifestOutcome = "invalid"
	ManifestUnreadable ManifestOutcome = "unreadable"
	ManifestOK         ManifestOutcome = "ok"
)

// OwnerState is issue #39's named local contract choice, not a vendor schema.
// Missing identifies no managed command, including a wholly replaced command.
type OwnerState string

const (
	OwnedExact        OwnerState = "owned_exact"
	OwnedModified     OwnerState = "owned_modified"
	OwnerMissing      OwnerState = "missing"
	OwnerFileMissing  OwnerState = "file_missing"
	OwnerUnreadable   OwnerState = "unreadable"
	OwnerNotEvaluated OwnerState = "not_evaluated"
)

type DriftEntry struct {
	Agent      string     `json:"agent"`
	Scope      string     `json:"scope"`
	Entry      string     `json:"entry"`
	OwnerState OwnerState `json:"ownerState"`
}

type DriftReport struct {
	Manifest ManifestOutcome `json:"manifest"`
	Entries  []DriftEntry    `json:"entries"`
}

// ClientDrift observes only snapshotted ownership, never effective vendor policy.
// All target I/O is relative to owner-validated handles (go.dev/blog/osroot).
// Expected filesystem/parser failures are typed outcomes, without raw error text.
func ClientDrift(home string) (DriftReport, error) {
	report := DriftReport{Manifest: ManifestUnreadable, Entries: []DriftEntry{}}
	if !filepath.IsAbs(home) {
		return report, nil
	}
	root, err := openDriftRoot(home)
	if err != nil {
		return report, nil
	}
	defer root.Close()
	data, err := readDriftFile(root, filepath.Join(".aegishook-client", "client.json"))
	if os.IsNotExist(err) {
		report.Manifest = ManifestAbsent
		return report, nil
	}
	if errors.Is(err, errDriftOversize) {
		report.Manifest = ManifestInvalid
		return report, nil
	}
	if err != nil {
		return report, nil
	}
	var manifest clientManifest
	if !validDriftJSON(data) || json.Unmarshal(data, &manifest) != nil || manifest.Format != 1 || len(manifest.NodeID) != 32 {
		report.Manifest = ManifestInvalid
		return report, nil
	}
	report.Manifest = ManifestOK
	roots := map[string]*os.Root{filepath.Clean(home): root}
	defer func() {
		for _, opened := range roots {
			if opened != nil && opened != root {
				_ = opened.Close()
			}
		}
	}()
	for _, entry := range manifest.Entries {
		state := OwnerNotEvaluated
		if entry.Agent != "cursor" || entry.Scope != "enterprise" {
			state = driftEntryState(home, root, roots, entry.Installation)
		}
		report.Entries = append(report.Entries, DriftEntry{Agent: entry.Agent, Scope: entry.Scope, Entry: entry.Entry, OwnerState: state})
	}
	return report, nil
}

func openDriftRoot(path string) (*os.Root, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	if err := validateDriftRoot(root); err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

func driftRelative(root, path string) (string, bool) {
	if !filepath.IsAbs(path) {
		return "", false
	}
	rel, err := filepath.Rel(root, path)
	return rel, err == nil && filepath.IsLocal(rel)
}

func driftTargetRoot(home string, homeRoot *os.Root, roots map[string]*os.Root, i Installation) (*os.Root, string) {
	base := home
	if i.Scope == "project" {
		base = i.Project
	} else if i.Scope != "global" {
		return nil, ""
	} else if _, inside := driftRelative(home, i.Entry); !inside {
		// A1: only recorded custom Pi/OpenCode roots have an external-root contract.
		suffix := ""
		switch i.Agent {
		case "pi":
			suffix = filepath.Join("extensions", "aegishook.ts")
		case "opencode":
			suffix = filepath.Join("plugins", "aegishook.js")
		}
		if suffix == "" || !strings.HasSuffix(i.Entry, string(filepath.Separator)+suffix) {
			return nil, ""
		}
		base = strings.TrimSuffix(i.Entry, string(filepath.Separator)+suffix)
	}
	if !filepath.IsAbs(base) {
		return nil, ""
	}
	base = filepath.Clean(base)
	rel, valid := driftRelative(base, i.Entry)
	if !valid {
		return nil, ""
	}
	root, seen := roots[base]
	if !seen {
		var err error
		if sub, inside := driftRelative(home, base); inside {
			root, err = homeRoot.OpenRoot(sub)
			if err == nil {
				err = validateDriftRoot(root)
				if err != nil {
					_ = root.Close()
				}
			}
		} else {
			root, err = openDriftRoot(base)
		}
		if err != nil {
			root = nil // Missing project/custom roots are unreadable, never file_missing.
		}
		roots[base] = root
	}
	return root, rel
}

func driftEntryState(home string, homeRoot *os.Root, roots map[string]*os.Root, i Installation) OwnerState {
	if AgentName(i.Agent) == "" {
		return OwnerUnreadable
	}
	root, rel := driftTargetRoot(home, homeRoot, roots, i)
	if root == nil {
		return OwnerUnreadable
	}
	if i.Agent == "pi" {
		return driftPi(root, rel, i.ManagedContent)
	}
	data, err := readDriftFile(root, rel)
	if os.IsNotExist(err) {
		return OwnerFileMissing
	}
	if err != nil {
		// #39 S1 review F2: oversize maps to unreadable, not a new owner state.
		return OwnerUnreadable
	}
	if i.Agent == "opencode" {
		if string(data) == i.ManagedContent {
			return OwnedExact
		}
		return OwnedModified
	}
	return driftGroups(data, i)
}

func readDriftFile(root *os.Root, rel string) ([]byte, error) {
	st, err := root.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("drift target is not regular")
	}
	file, err := openDriftFile(root, rel)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	st, err = file.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("opened drift target is not regular")
	}
	// policy_bundle_cache.go's cap+1 pattern detects oversize without trusting
	// a possibly stale Stat size or accepting a truncated, valid JSON prefix.
	data, err := io.ReadAll(io.LimitReader(file, clientDriftMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > clientDriftMaxBytes {
		return nil, errDriftOversize
	}
	return data, nil
}

func driftPi(root *os.Root, rel, target string) OwnerState {
	st, err := root.Lstat(rel)
	if os.IsNotExist(err) {
		return OwnerFileMissing
	}
	if err != nil {
		return OwnerUnreadable
	}
	if st.Mode()&os.ModeSymlink != 0 {
		link, err := root.Readlink(rel) // Explicit Pi exception: never follow the link.
		if err != nil {
			return OwnerUnreadable
		}
		if link == target {
			return OwnedExact
		}
		return OwnedModified
	}
	if st.Mode().IsRegular() {
		return OwnedModified // Pi ownership is link identity; regular bytes are irrelevant.
	}
	return OwnerUnreadable
}

func driftGroups(data []byte, i Installation) OwnerState {
	var doc map[string]any
	if json.Unmarshal(data, &doc) != nil || doc == nil || i.ManagedCommand == "" {
		return OwnerUnreadable
	}
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		if _, exists := doc["hooks"]; exists {
			return OwnerUnreadable
		}
		return OwnerMissing
	}
	state := OwnedExact
	for _, event := range hookEvents(i.Agent) {
		want := hookGroup(i, event)
		if len(want) == 0 {
			return OwnerUnreadable
		}
		list, ok := hooks[event].([]any)
		if !ok {
			if _, exists := hooks[event]; exists {
				return OwnerUnreadable
			}
		}
		found := false
		for _, group := range list {
			if bytes.Equal(mustJSON(group), mustJSON(want)) {
				found = true
			}
		}
		if !found {
			state = OwnerMissing
		}
	}
	// Match install_agents.go's serialized-command identity, including mixed siblings.
	command := []byte(strings.Trim(string(mustJSON(i.ManagedCommand)), "\""))
	for event, value := range hooks {
		list, ok := value.([]any)
		if !ok {
			return OwnerUnreadable
		}
		for _, group := range list {
			encoded := mustJSON(group)
			if bytes.Contains(encoded, command) && (!bytes.Equal(encoded, mustJSON(hookGroup(i, event))) || i.Agent == "cursor" && doc["version"] != float64(1)) {
				return OwnedModified
			}
		}
	}
	return state
}

// RFC 8259 §4 / RFC 7493 §2.3: reject duplicate decoded member names before
// encoding/json can merge them. Case-folding also rejects Go field aliases.
// Ported from #38/41 S1 discovery/report.go checkJSONValue/foldMemberName;
// that private helper/package is unavailable at this worktree's frozen base.
func validDriftJSON(data []byte) bool {
	// json.Valid enforces encoding/json's own nesting bound before recursion;
	// Decoder.Token alone does not apply the scanner's maxNestingDepth guard.
	if !json.Valid(data) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if checkDriftJSONValue(decoder) != nil {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func checkDriftJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name := foldDriftMemberName(key.(string))
			if seen[name] {
				return errors.New("duplicate JSON member")
			}
			seen[name] = true
			if err := checkDriftJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
	case json.Delim('['):
		for decoder.More() {
			if err := checkDriftJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
	}
	return err
}

func foldDriftMemberName(name string) string {
	return strings.Map(func(r rune) rune {
		for next := unicode.SimpleFold(r); next > r; next = unicode.SimpleFold(r) {
			r = next
		}
		return unicode.SimpleFold(r)
	}, name)
}
