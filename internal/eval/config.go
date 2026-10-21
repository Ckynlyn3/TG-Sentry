package eval

import (
	"aegishook/internal/core"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

const FreezeTag = "eval-freeze-m3-v1" // Approved plan §2.
const SchemaVersion = 1               // Initial schema version, plan §2 local manifest contract.

type Manifest struct {
	Version int       `json:"version"`
	Sets    []Dataset `json:"sets"`
}
type Dataset struct {
	Name                  string        `json:"name"`
	SourceURL             string        `json:"source_url"`
	Revision              string        `json:"revision"`
	LicenseCode           string        `json:"license_code"`
	LicenseData           string        `json:"license_data"`
	Admissible            bool          `json:"admissible"`
	AdmissibilityReason   string        `json:"admissibility_reason"`
	Languages             []string      `json:"languages"`
	LanguageMetadataLevel string        `json:"language_metadata_level"`
	Category              string        `json:"category"`
	Categories            []string      `json:"categories"`
	Mode                  string        `json:"mode"`
	SplitUse              string        `json:"split_use"`
	ItemCountDeclared     *int          `json:"item_count_declared"`
	CountNotes            string        `json:"count_notes"`
	ExposureCount         int           `json:"exposure_count"`
	Synthetic             *Synthetic    `json:"synthetic"`
	Fetch                 []Fetch       `json:"fetch"`
	Files                 []PendingFile `json:"files"`
	FieldMap              *FieldMap     `json:"field_map"`
}
type Synthetic struct {
	Generator string `json:"generator"`
	DevSeed   string `json:"dev_seed"`
}
type Fetch struct {
	URLOrPath string `json:"url_or_path"`
}
type PendingFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// FieldMap is lead-approved key/column metadata, not a content-derived label.
type FieldMap struct {
	Format   string `json:"format"`
	Text     string `json:"text"`
	Language string `json:"language,omitempty"`
	Label    bool   `json:"label"`
	Category string `json:"category"`
	Surface  string `json:"surface"`
}
type Lock struct {
	Version        int                 `json:"version"`
	ManifestSHA256 string              `json:"manifest_sha256"`
	ConfigSHA256   string              `json:"config_sha256"`
	AcceptanceSeed string              `json:"acceptance_seed"`
	TreeHash       string              `json:"tree_hash"`
	Files          []LockedFile        `json:"files"`
	FieldMaps      map[string]FieldMap `json:"field_maps,omitempty"`
}
type LockedFile struct {
	Dataset   string    `json:"dataset"`
	Path      string    `json:"path"`
	URL       string    `json:"url"`
	SHA256    string    `json:"sha256"`
	Bytes     int64     `json:"bytes"`
	FetchedAt time.Time `json:"fetched_at"`
	// Member selects an exact archive member, never an extraction destination.
	Member  string `json:"member,omitempty"`
	Variant string `json:"variant,omitempty"`
}
type FrozenConfig struct {
	Version       int               `json:"version"`
	Settings      core.Settings     `json:"settings"`
	Rules         []core.Rule       `json:"rules"`
	Scopes        []core.Scope      `json:"scopes"`
	RulesSHA256   string            `json:"rules_sha256"`
	CatalogSHA256 string            `json:"catalog_sha256"`
	Digests       map[string]string `json:"digests"`
	// Component metadata records image/model revisions, profiles and prompts; the
	// integration supplies independently obtained live digests to Run.
	Components         map[string]json.RawMessage `json:"components"`
	Environment        map[string]string          `json:"environment"`
	TagMapping         map[string][]string        `json:"tag_mapping"`
	LabelMapping       map[string]string          `json:"label_mapping"`
	Thresholds         []Threshold                `json:"thresholds"`
	GOMAXPROCS         int                        `json:"gomaxprocs"`
	CPUCount           int                        `json:"cpu_count"`
	HostClass          string                     `json:"host_class"`
	Lambda             *float64                   `json:"lambda"`
	NSFAEnforce        bool                       `json:"nsfa_enforce"`
	JudgeSeedSupported bool                       `json:"judge_seed_supported"`
	PollIntervalMS     int                        `json:"poll_interval_ms"`
}
type Threshold struct {
	ID         string   `json:"id"`
	Dataset    string   `json:"dataset"`
	Category   string   `json:"category"`
	Language   string   `json:"language"`
	EntityType string   `json:"entity_type,omitempty"`
	Variant    string   `json:"variant,omitempty"`
	Metric     string   `json:"metric"`
	Operator   string   `json:"operator"`
	Bound      *float64 `json:"bound"`
	ReportOnly bool     `json:"report_only"`
	Source     string   `json:"source"`
}

// Decode rejects unknown keys, trailing JSON, and null documents. No parser
// errors echo values from untrusted inputs into logs or reports.
func Decode(r io.Reader, out any) error {
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	raw := json.RawMessage{}
	if err := d.Decode(&raw); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("invalid JSON document")
	}
	nested := json.NewDecoder(bytes.NewReader(raw))
	nested.DisallowUnknownFields()
	if err := nested.Decode(out); err != nil {
		return errors.New("invalid document schema")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func Load(path string, out any) error {
	f, e := os.Open(path)
	if e != nil {
		return errors.New("cannot open evaluation document")
	}
	defer f.Close()
	return Decode(f, out)
}
func Digest(v any) string {
	b, e := json.Marshal(v)
	if e != nil {
		return ""
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func HashFile(path string) (string, int64, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	return hashReader(f)
}
func hashReader(r io.Reader) (string, int64, error) {
	h := sha256.New()
	n, e := io.Copy(h, r)
	return hex.EncodeToString(h.Sum(nil)), n, e
}
func validHash(h string) bool {
	b, e := hex.DecodeString(h)
	return e == nil && len(b) == sha256.Size && strings.ToLower(h) == h
}
func CheckDigests(frozen, live map[string]string) error {
	if !reflect.DeepEqual(frozen, live) {
		return errors.New("live detector config digest drift")
	}
	for _, v := range frozen {
		if !validHash(v) {
			return errors.New("missing detector config digest")
		}
	}
	return nil
}
func CheckGit(root string) (string, error) {
	if err := rejectHiddenIndex(root); err != nil {
		return "", err
	}
	git := func(args ...string) (string, error) {
		b, e := validationGit(root, args...)
		return strings.TrimSpace(string(b)), e
	}
	dirty, e := git("status", "--porcelain", "--untracked-files=all")
	if e != nil || dirty != "" {
		return "", errors.New("evaluation requires a clean git tree")
	}
	head, e := git("rev-parse", "HEAD")
	if e != nil {
		return "", errors.New("cannot resolve HEAD")
	}
	tag, e := git("rev-parse", "refs/tags/"+FreezeTag+"^{commit}")
	if e != nil {
		return "", errors.New("freeze tag missing")
	}
	if head == tag {
		return head, nil
	}
	parent, e := git("rev-parse", "HEAD^")
	if e != nil || parent != tag {
		return "", errors.New("HEAD is not freeze tag or direct lock-only descendant")
	}
	parents, e := git("rev-list", "--parents", "-n", "1", "HEAD")
	if e != nil || len(strings.Fields(parents)) != 2 {
		return "", errors.New("lock commit must have exactly one parent")
	}
	diff, e := git("diff", "--name-only", tag, head)
	if e != nil || diff != "eval/manifest.lock.json" {
		return "", errors.New("non-lock change after freeze")
	}
	return head, nil
}

// Tree hash follows golang.org/x/mod/sumdb/dirhash.Hash1's sorted
// "<sha256>  <path>\n" lines, hashing bytes rather than filesystem metadata.
func VerifyFiles(root string, files []LockedFile) (string, error) {
	dir, e := os.OpenRoot(root)
	if e != nil {
		return "", errors.New("sealed directory unavailable")
	}
	defer dir.Close()
	rows := map[string]string{}
	for _, v := range files {
		if !filepath.IsLocal(v.Path) || strings.ContainsAny(v.Path, "\n\r") || !validHash(v.SHA256) || v.Bytes < 0 {
			return "", errors.New("invalid locked file")
		}
		if old, ok := rows[v.Path]; ok {
			if old != v.SHA256 {
				return "", errors.New("conflicting file pin")
			}
			continue
		}
		info, e := dir.Lstat(v.Path)
		if e != nil || !info.Mode().IsRegular() {
			return "", errors.New("sealed file must be regular, not a symlink")
		}
		f, e := dir.Open(v.Path)
		if e != nil {
			return "", errors.New("cannot read sealed file")
		}
		hash, n, err := hashReader(f)
		ce := f.Close()
		if err != nil || ce != nil || hash != v.SHA256 || n != v.Bytes {
			return "", errors.New("sealed file hash or byte-count mismatch")
		}
		rows[v.Path] = hash
	}
	if err := fs.WalkDir(dir.FS(), ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("cannot inventory sealed directory")
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() || rows[path] == "" {
			return errors.New("unhashed or nonregular file in sealed directory")
		}
		return nil
	}); err != nil {
		return "", err
	}
	paths := make([]string, 0, len(rows))
	for p := range rows {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		fmt.Fprintf(h, "%s  %s\n", rows[p], p)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (m Manifest) Validate() error {
	if m.Version != SchemaVersion || len(m.Sets) == 0 {
		return errors.New("unsupported or empty manifest")
	}
	names := map[string]bool{}
	for _, s := range m.Sets {
		if s.Name == "" || names[s.Name] || s.SourceURL == "" || s.Revision == "" || s.AdmissibilityReason == "" || s.ExposureCount < 0 {
			return errors.New("invalid manifest entry")
		}
		names[s.Name] = true
		if s.SplitUse != "held_out" && s.SplitUse != "dev" {
			return errors.New("invalid split use")
		}
		if s.Mode == "full-path" {
			return errors.New("no admissible dataset supplies native review input (gap)")
		}
		if s.Mode != "detector-level" && s.Mode != "judge" {
			return errors.New("invalid evaluation mode")
		}
		if s.LanguageMetadataLevel != "none" && s.LanguageMetadataLevel != "set" && s.LanguageMetadataLevel != "item" {
			return errors.New("invalid language metadata level")
		}
		if s.SplitUse == "dev" && (s.Synthetic == nil || s.Synthetic.DevSeed != "dev") {
			return errors.New("dev fixtures require dev seed")
		}
	}
	return nil
}
func (c FrozenConfig) Validate(live map[string]string) error {
	if c.Version != SchemaVersion || c.RulesSHA256 != Digest(c.Rules) || c.CatalogSHA256 != Digest(core.BuiltinRules()) {
		return errors.New("rule snapshot or catalog digest drift")
	}
	if err := CheckDigests(c.Digests, live); err != nil {
		return err
	}
	if c.GOMAXPROCS <= 0 || c.CPUCount <= 0 || c.HostClass == "" || c.PollIntervalMS <= 0 {
		return errors.New("hardware/poll settings must be explicit")
	}
	actualEnv := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok && strings.HasPrefix(key, "TG_NSFA_GUARD_") {
			actualEnv[key] = value
		}
	}
	if len(actualEnv) != len(c.Environment) {
		return errors.New("NSFA environment drift")
	}
	for k, v := range c.Environment {
		actualValue, exists := actualEnv[k]
		if !strings.HasPrefix(k, "TG_NSFA_GUARD_") || !exists || actualValue != v {
			return errors.New("NSFA environment drift")
		}
	}
	if c.NSFAEnforce && (c.Lambda == nil || *c.Lambda <= 0) {
		return errors.New("enforce requires declared peak lambda")
	}
	for _, th := range c.Thresholds {
		if th.ID == "" || th.Source == "" || (!th.ReportOnly && (th.Bound == nil || (th.Operator != "<=" && th.Operator != ">="))) {
			return errors.New("invalid frozen threshold")
		}
	}
	return nil
}

func checkDocument(root, path, expected string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return errors.New("invalid document root")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(absRoot, path)
	}
	if filepath.Clean(path) != filepath.Join(absRoot, filepath.FromSlash(expected)) {
		return errors.New("evaluation document must use tracked canonical path")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("evaluation document must be a regular tracked file")
	}
	if err = rejectHiddenIndex(absRoot); err != nil {
		return err
	}
	b, err := validationGit(absRoot, "show", "HEAD:"+expected)
	if err != nil {
		return errors.New("evaluation document not tracked")
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(b, actual) {
		return errors.New("evaluation document differs from HEAD")
	}
	return nil
}

// Git documents clearing repository-local environment when operating on another
// worktree (githooks DESCRIPTION; rev-parse --local-env-vars). Clear all GIT_*
// overrides, including config/index/object/namespace overrides, and explicitly
// bind the legitimate gitfile (also valid for linked worktrees) and work tree.
// https://git-scm.com/docs/githooks#_description
func validationGit(root string, args ...string) ([]byte, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	// core.fsmonitor lets an external hook report "no changes"; validation must
	// stat the work tree itself. https://git-scm.com/docs/git-config#Documentation/git-config.txt-corefsmonitor
	flags := []string{"-C", abs, "--git-dir=" + filepath.Join(abs, ".git"), "--work-tree=" + abs, "-c", "core.fsmonitor=false"}
	cmd := exec.Command("git", append(flags, args...)...)
	cmd.Dir = abs
	cmd.Env = []string{}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(strings.ToUpper(key), "GIT_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	return cmd.Output()
}

// -v lowercases assume-unchanged entries; S marks skip-worktree entries.
// Reject both, rather than trusting status's intentionally suppressed checks.
// https://git-scm.com/docs/git-ls-files#Documentation/git-ls-files.txt--v
func rejectHiddenIndex(root string) error {
	out, err := validationGit(root, "ls-files", "-v", "-z")
	if err != nil {
		return errors.New("cannot verify evaluation index flags")
	}
	for _, entry := range bytes.Split(out, []byte{0}) {
		if len(entry) > 0 && (entry[0] == 'S' || (entry[0] >= 'a' && entry[0] <= 'z')) {
			return errors.New("evaluation rejects assume-unchanged/skip-worktree index entries")
		}
	}
	return nil
}
