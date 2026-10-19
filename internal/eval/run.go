package eval

import (
	"aegishook/internal/core"
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type RunOptions struct {
	Root, Manifest, Lock, Config, SealedDir, Out string
	Detector                                     Detector
	// Must be obtained from the integrated live detector, NOT copied from config.
	LiveDigests map[string]string
}

func Run(ctx context.Context, o RunOptions) (Report, error) {
	return runOnHost(ctx, o, runtime.GOOS, runtime.GOARCH)
}

// Host injection is private and used only by synthetic state-machine tests;
// Run always binds it to the actual platform, with no bypass flag/environment.
func runOnHost(ctx context.Context, o RunOptions, goos, goarch string) (rep Report, runErr error) {
	rep = Report{Version: SchemaVersion, Tag: FreezeTag, StartedAt: time.Now().UTC(), Nondeterministic: true, Exposure: map[string]int{}, Digests: map[string]string{}}
	head, err := CheckGit(o.Root)
	if err != nil {
		return rep, err
	}
	rep.HEAD = head
	var m Manifest
	var lock Lock
	var c FrozenConfig
	for _, doc := range []struct {
		path, key, expected string
		target              any
	}{{o.Manifest, "manifest", "eval/manifest.json", &m}, {o.Lock, "lock", "eval/manifest.lock.json", &lock}, {o.Config, "config", "eval/config.frozen.json", &c}} {
		if err = checkDocument(o.Root, doc.path, doc.expected); err != nil {
			return rep, err
		}
		path := doc.path
		if !filepath.IsAbs(path) {
			path = filepath.Join(o.Root, path)
		}
		if err = Load(path, doc.target); err != nil {
			return rep, err
		}
		h, _, e := HashFile(path)
		if e != nil {
			return rep, errors.New("cannot hash evaluation documents")
		}
		rep.Digests[doc.key] = h
	}
	if err = m.Validate(); err != nil {
		return rep, err
	}
	if err = c.Validate(o.LiveDigests); err != nil {
		return rep, err
	}
	if lock.Version != SchemaVersion || lock.ManifestSHA256 != rep.Digests["manifest"] || lock.ConfigSHA256 != rep.Digests["config"] || len(lock.Files) == 0 {
		return rep, errors.New("manifest/config lock digest drift or empty lock")
	}
	if goos != "linux" || goarch != "amd64" {
		return rep, errors.New("final evaluation requires Linux amd64")
	}
	if runtime.NumCPU() != c.CPUCount || runtime.GOMAXPROCS(0) != c.GOMAXPROCS {
		return rep, errors.New("frozen hardware/config drift")
	}
	rep.Hardware = map[string]any{"goos": goos, "goarch": goarch, "go_version": runtime.Version(), "cpu_count": runtime.NumCPU(), "gomaxprocs": runtime.GOMAXPROCS(0), "host_class": c.HostClass, "lambda": c.Lambda}
	tree, err := VerifyFiles(o.SealedDir, lock.Files)
	if err != nil {
		return rep, err
	}
	if tree != lock.TreeHash {
		return rep, errors.New("sealed directory tree hash mismatch")
	}
	sets := map[string]Dataset{}
	for _, s := range m.Sets {
		sets[s.Name] = s
		if s.Admissible && s.SplitUse == "held_out" {
			if s.Category == "category::prompt-attack" && len(c.TagMapping[s.Name]) == 0 {
				return rep, errors.New("frozen prompt tag mapping missing")
			}
			if s.Category == "category::sensitive-info" && len(c.LabelMapping) == 0 {
				return rep, errors.New("frozen entity label mapping missing")
			}
		}
		rep.Exposure[s.Name] = s.ExposureCount
	}
	// Preflight ALL files/adapters before any Detect/Submit. A malformed late set
	// is an operational STOP, never a partially scored held-out run.
	items := map[string][]Item{}
	for _, f := range lock.Files {
		s, ok := sets[f.Dataset]
		if !ok || !s.Admissible {
			return rep, errors.New("locked dataset not admissible")
		}
		if field, ok := lock.FieldMaps[s.Name]; ok {
			s.FieldMap = &field
		}
		rows, e := readLocked(o.SealedDir, f, s)
		if e != nil {
			return rep, e
		}
		items[s.Name] = append(items[s.Name], rows...)
	}
	for _, s := range m.Sets {
		if s.Admissible && s.SplitUse == "held_out" && len(items[s.Name]) == 0 {
			return rep, errors.New("admissible held-out set missing from lock")
		}
	}
	for name, rows := range items {
		if err = checkScoringCount(name, len(rows)); err != nil {
			return rep, err
		}
		if sets[name].Mode == "full-path" || sets[name].Mode == "judge" {
			for _, row := range rows {
				if row.Review == nil {
					return rep, errors.New("full-path adapter requires native ReviewInput records")
				}
			}
		}
		if err = sortUnique(rows); err != nil {
			return rep, err
		}
		if len(rows) == 0 {
			return rep, errors.New("empty dataset")
		}
		items[name] = rows
	}
	for _, s := range m.Sets {
		if s.Name == "PII-acceptance" && len(items[s.Name]) > 0 {
			if lock.AcceptanceSeed == "" || lock.AcceptanceSeed == "dev" {
				return rep, errors.New("sealed acceptance seed required and distinct from dev")
			}
			for _, row := range items[s.Name] {
				if row.Seed != lock.AcceptanceSeed {
					return rep, errors.New("acceptance seed differs from sealed lock")
				}
			}
		}
	}
	if err = os.Mkdir(o.Out, 0700); err != nil {
		return rep, errors.New("output directory must be new before scoring")
	}
	e, cleanup, err := OpenIsolated(c, "")
	if err != nil {
		return rep, err
	}
	defer func() { runErr = errors.Join(runErr, cleanup()) }()
	det := o.Detector
	if det == nil {
		det = noopDetector{}
	}
	cold := []float64{}
	// WARMUP-20 is the approved local exception, never held-out. Exactly the
	// generator's dev records; caller cannot substitute held-out warmup data.
	dev := GenerateDev()
	for i, row := range dev {
		item := Item{ID: row.ID, Input: Input{Text: row.Text, Language: row.Language, Surface: row.Surface, Tenant: "eval"}, Gold: row.Entities}
		obs, err := observe(ctx, Dataset{Mode: "detector-level"}, item, c, e, det)
		if err != nil {
			return rep, err
		}
		cold = append(cold, obs.LatencyMS)
		rep.WarmupN = i + 1
	}
	all := []Observation{}
	for _, s := range m.Sets {
		if s.SplitUse == "dev" {
			continue
		}
		rows := []Observation{}
		for _, item := range items[s.Name] {
			obs, e2 := observe(ctx, s, item, c, e, det)
			if e2 != nil {
				return rep, e2
			}
			rows = append(rows, obs)
			all = append(all, obs)
		}
		if len(rows) > 0 {
			rep.Exposure[s.Name]++
		}
		// Categories is provenance only. Injection labels are not scoped high-risk
		// operation labels; T8 needs its own explicit scoped fixture ground truth.
		groups := Summarize(s, rows, c)
		for i := range groups {
			if s.Mode == "detector-level" {
				groups[i].ColdLatency = latency(cold[:1])
			}
		}
		rep.Groups = append(rep.Groups, groups...)
	}
	rep.Thresholds = EvaluateThresholds(c.Thresholds, rep.Groups)
	rep.FinishedAt = time.Now().UTC()
	if err = writeReportFiles(o.Out, rep, all); err != nil {
		return rep, err
	}
	return rep, nil
}
func sortUnique(rows []Item) error {
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	for i := 1; i < len(rows); i++ {
		if rows[i].ID == rows[i-1].ID {
			return errors.New("duplicate item identity")
		}
	}
	return nil
}
func observe(ctx context.Context, s Dataset, item Item, c FrozenConfig, e *core.Engine, det Detector) (Observation, error) {
	obs := Observation{Item: item}
	if ctx.Err() != nil {
		return obs, errors.New("evaluation cancelled")
	}
	if s.Mode == "judge" || s.Mode == "full-path" {
		path, err := FullPath(ctx, e, item, time.Duration(c.PollIntervalMS)*time.Millisecond)
		if err != nil {
			return obs, err
		}
		obs.LatencyMS = path.LatencyMS
		obs.ReviewPath = path.ReviewPath
		obs.Result = Result{Decision: path.Decision, Unavailable: path.UnavailableReason != "", Reason: path.UnavailableReason}
		obs.Result.Decision, err = outputDecision(obs.Result.Decision, obs.Result.Unavailable)
		return obs, err
	}
	start := time.Now()
	result, err := det.Detect(ctx, item.Input)
	obs.LatencyMS = float64(time.Since(start)) / float64(time.Millisecond)
	if err != nil {
		result = Result{Unavailable: true, Reason: "detector_error"}
	}
	result.Decision, err = outputDecision(result.Decision, result.Unavailable)
	if err != nil {
		return obs, err
	}
	if !result.Unavailable {
		if err = ValidateEntities(item.Input.Text, predEntities(result)); err != nil {
			return obs, err
		}
	}
	for _, finding := range result.Findings {
		for _, tag := range c.TagMapping[s.Name] {
			if finding.Tag == tag {
				obs.Tags = append(obs.Tags, tag)
				break
			}
		}
	}
	obs.Result = result
	return obs, nil
}
func readLocked(root string, f LockedFile, s Dataset) ([]Item, error) {
	dir, err := os.OpenRoot(root)
	if err != nil {
		return nil, errors.New("sealed directory unavailable")
	}
	defer dir.Close()
	file, err := dir.Open(f.Path)
	if err != nil {
		return nil, errors.New("sealed file unavailable")
	}
	defer file.Close()
	// ponytail: one in-memory archive snapshot binds parser bytes to their hash;
	// use an authenticated immutable backing file if inputs exceed memory.
	payload, err := io.ReadAll(file)
	if err != nil {
		return nil, errors.New("cannot snapshot sealed input")
	}
	snapshot := bytes.NewReader(payload)
	h, n, err := hashReader(snapshot)
	if err != nil || h != f.SHA256 || n != f.Bytes {
		return nil, errors.New("sealed file changed before parse")
	}
	snapshot.Reset(payload)
	if f.Member == "" {
		return Adapt(snapshot, s, f)
	}
	if !filepath.IsLocal(f.Member) {
		return nil, errors.New("invalid archive member")
	}
	if strings.HasSuffix(f.Path, ".zip") {
		z, err := zip.NewReader(snapshot, n)
		if err != nil {
			return nil, errors.New("invalid ZIP archive")
		}
		var selected *zip.File
		for _, member := range z.File {
			if member.Name == f.Member {
				if selected != nil || !member.Mode().IsRegular() {
					return nil, errors.New("ambiguous or nonregular ZIP member")
				}
				selected = member
			}
		}
		if selected == nil {
			return nil, errors.New("locked ZIP member missing")
		}
		r, err := selected.Open()
		if err != nil {
			return nil, errors.New("cannot open ZIP member")
		}
		defer r.Close()
		return Adapt(r, s, f)
	}
	var reader io.Reader = snapshot
	if strings.HasSuffix(f.Path, ".gz") {
		g, err := gzip.NewReader(snapshot)
		if err != nil {
			return nil, errors.New("invalid gzip archive")
		}
		defer g.Close()
		reader = g
	}
	t := tar.NewReader(reader)
	var selected []byte
	for {
		header, err := t.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("invalid tar archive")
		}
		if header.Name == f.Member {
			if selected != nil || header.Typeflag != tar.TypeReg {
				return nil, errors.New("ambiguous or nonregular tar member")
			}
			selected, err = io.ReadAll(t)
			if err != nil {
				return nil, errors.New("cannot read tar member")
			}
		}
	}
	if selected == nil {
		return nil, errors.New("locked tar member missing")
	}
	return Adapt(bytes.NewReader(selected), s, f)
}

// Exact item counts from the approved issue26 plan §1 table: NotInject =
// 113 × 3 = 339 (arXiv 2410.22770), CPAD = 10,050 (arXiv 2309.11830).
// AgentDojo security cases and InjecAgent per-setting counts are not this
// adapter's aggregate scoring units, so remain provenance only.
func checkScoringCount(name string, n int) error {
	var expected int
	switch name {
	case "NotInject":
		expected = 339
	case "CPAD":
		expected = 10050
	default:
		return nil
	}
	if n != expected {
		return fmt.Errorf("%s scoring-unit count mismatch: got %d, want %d", name, n, expected)
	}
	return nil
}
