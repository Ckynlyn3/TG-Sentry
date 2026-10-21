package eval

import (
	"aegishook/internal/core"
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type fakeDetector struct {
	calls  int
	fail   bool
	result Result
}

func (d *fakeDetector) Detect(context.Context, Input) (Result, error) {
	d.calls++
	if d.fail {
		return Result{}, errors.New("SENSITIVE FAKE TEXT must never leave error")
	}
	return d.result, nil
}
func writeJSONTest(t *testing.T, p string, v any) {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func syntheticRun(t *testing.T) (RunOptions, FrozenConfig) {
	t.Helper()
	root := t.TempDir()
	sealed := t.TempDir()
	os.Mkdir(filepath.Join(root, "eval"), 0700)
	s := Dataset{Name: "NotInject", SourceURL: "synthetic-only", Revision: "synthetic", Admissible: true, AdmissibilityReason: "fake dev test, never benchmark data", SplitUse: "held_out", Mode: "detector-level", Category: "category::prompt-attack", Categories: []string{"category::prompt-attack", "category::high-risk-ops"}, LanguageMetadataLevel: "none"}
	c := testConfig()
	c.GOMAXPROCS = runtime.GOMAXPROCS(0)
	c.CPUCount = runtime.NumCPU()
	c.TagMapping = map[string][]string{s.Name: {"1"}}
	m := Manifest{Version: 1, Sets: []Dataset{s}}
	o := RunOptions{Root: root, Manifest: filepath.Join(root, "eval/manifest.json"), Config: filepath.Join(root, "eval/config.frozen.json"), Lock: filepath.Join(root, "eval/manifest.lock.json"), SealedDir: sealed, Out: filepath.Join(t.TempDir(), "results"), Detector: &fakeDetector{result: Result{Decision: "approve"}}}
	writeJSONTest(t, o.Manifest, m)
	writeJSONTest(t, o.Config, c)
	// Synthetic git repository only. Never tags or commits the project checkout.
	gitTest(t, root, "init")
	gitTest(t, root, "add", ".")
	gitTest(t, root, "commit", "-m", "synthetic freeze")
	gitTest(t, root, "tag", FreezeTag)
	// Plan §1 requires 339 NotInject scoring units. Repeat one obviously fake
	// phrase for count plumbing, never benchmark content.
	fakeRows := make([]map[string]string, 339)
	for i := range fakeRows {
		fakeRows[i] = map[string]string{"prompt": "FAKE synthetic benign count-only record"}
	}
	data, err := json.Marshal(fakeRows)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(sealed, "fake.json"), data, 0600)
	h, n, _ := HashFile(filepath.Join(sealed, "fake.json"))
	f := LockedFile{Dataset: s.Name, Path: "fake.json", URL: "synthetic", SHA256: h, Bytes: n}
	tree, e := VerifyFiles(sealed, []LockedFile{f})
	if e != nil {
		t.Fatal(e)
	}
	mh, _, _ := HashFile(o.Manifest)
	ch, _, _ := HashFile(o.Config)
	writeJSONTest(t, o.Lock, Lock{Version: 1, ManifestSHA256: mh, ConfigSHA256: ch, TreeHash: tree, Files: []LockedFile{f}})
	gitTest(t, root, "add", ".")
	gitTest(t, root, "commit", "-m", "synthetic lock")
	return o, c
}
func TestRunSyntheticOnceAndWarmupDevOnly(t *testing.T) {
	o, _ := syntheticRun(t)
	r, e := Run(context.Background(), o)
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		if e == nil {
			t.Fatal("platform guard")
		}
		r, e = runOnHost(context.Background(), o, "linux", "amd64")
	}
	if e != nil {
		t.Fatal(e)
	}
	if r.WarmupN != 20 || o.Detector.(*fakeDetector).calls != 20+339 || len(r.Groups) != 1 || r.Groups[0].NScored != 339 || !r.Nondeterministic {
		t.Fatal(r)
	}
	if _, e := os.Stat(filepath.Join(o.Out, "report.md")); e != nil {
		t.Fatal(e)
	}
}
func TestRunPreflightRefusalsBeforeDetector(t *testing.T) {
	for _, mode := range []string{"dirty", "hash", "config", "tree", "manifest", "missing", "inadmissible"} {
		t.Run(mode, func(t *testing.T) {
			o, _ := syntheticRun(t)
			var lock Lock
			if e := Load(o.Lock, &lock); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "dirty":
				os.WriteFile(filepath.Join(o.Root, "dirty"), []byte("fake"), 0600)
			case "hash":
				os.WriteFile(filepath.Join(o.SealedDir, "fake.json"), []byte("changed"), 0600)
			case "config":
				o.LiveDigests = map[string]string{"drift": strings.Repeat("a", 64)}
			case "tree":
				lock.TreeHash = strings.Repeat("0", 64)
			case "manifest":
				lock.ManifestSHA256 = strings.Repeat("0", 64)
			case "missing":
				lock.Files = nil
			case "inadmissible":
				lock.Files[0].Dataset = "unknown"
			}
			if mode == "tree" || mode == "manifest" || mode == "missing" || mode == "inadmissible" {
				writeJSONTest(t, o.Lock, lock)
				gitTest(t, o.Root, "add", ".")
				gitTest(t, o.Root, "commit", "--amend", "--no-edit")
			}
			_, e := runOnHost(context.Background(), o, "linux", "amd64")
			if e == nil || o.Detector.(*fakeDetector).calls != 0 {
				t.Fatal("preflight failed", e)
			}
		})
	}
}
func TestArchiveReadersUsePinnedBytesNoExtraction(t *testing.T) {
	root := t.TempDir()
	data := []byte(`[{"prompt":"FAKE archive record"}]`)
	for _, ext := range []string{".json", ".zip", ".tar", ".tar.gz"} {
		t.Run(ext, func(t *testing.T) {
			var b bytes.Buffer
			switch ext {
			case ".json":
				b.Write(data)
			case ".zip":
				w := zip.NewWriter(&b)
				f, _ := w.Create("fake.json")
				f.Write(data)
				w.Close()
			case ".tar", ".tar.gz":
				var dest io.Writer = &b
				var gz *gzip.Writer
				if ext == ".tar.gz" {
					gz = gzip.NewWriter(&b)
					dest = gz
				}
				w := tar.NewWriter(dest)
				w.WriteHeader(&tar.Header{Name: "fake.json", Mode: 0600, Size: int64(len(data))})
				w.Write(data)
				w.Close()
				if gz != nil {
					gz.Close()
				}
			}
			p := "fake" + ext
			os.WriteFile(filepath.Join(root, p), b.Bytes(), 0600)
			h, n, _ := HashFile(filepath.Join(root, p))
			f := LockedFile{Path: p, SHA256: h, Bytes: n}
			if ext != ".json" {
				f.Member = "fake.json"
			}
			rows, e := readLocked(root, f, Dataset{Name: "NotInject"})
			if e != nil || len(rows) != 1 {
				t.Fatal(rows, e)
			}
			f.SHA256 = strings.Repeat("0", 64)
			if _, e = readLocked(root, f, Dataset{Name: "NotInject"}); e == nil {
				t.Fatal("unverified parse")
			}
		})
	}
}
func TestObserveAndThresholdVectors(t *testing.T) {
	c := testConfig()
	ctx := context.Background()
	d := &fakeDetector{fail: true}
	o, e := observe(ctx, Dataset{}, Item{}, c, nil, d)
	if e != nil || !o.Result.Unavailable || o.Result.Reason != "detector_error" {
		t.Fatal(o, e)
	}
	d.fail = false
	d.result = Result{Decision: "invalid"}
	if _, e = observe(ctx, Dataset{}, Item{}, c, nil, d); e == nil {
		t.Fatal("invalid decision")
	}
	e1, cleanup, e := OpenIsolated(c, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer cleanup()
	o, e = observe(ctx, Dataset{Mode: "full-path"}, Item{ID: "fake", Review: &core.ReviewInput{ToolName: "Read", Arguments: map[string]any{"file_path": "README.md"}}}, c, e1, d)
	if e != nil || o.ReviewPath != "rule" {
		t.Fatal(o, e)
	}
	g := Group{Dataset: "fake", Category: "category::prompt-attack", Language: "EN", Precision: Proportion(3, 4), Recall: Proportion(3, 5), BenignBlockRate: Proportion(1, 4), Latency: latency([]float64{1, 2, 3}), Entities: map[string]EntityMetric{"Email": {CharacterF1: floatPtr(.9)}}}
	for _, tc := range []struct {
		metric string
		bound  float64
		status string
	}{{"precision", .7, "PASS"}, {"recall", .7, "FAIL"}, {"benign_block_rate", .2, "PASS"}, {"benign_acceptance", .7, "PASS"}, {"latency_p95_ms", 2, "PASS"}, {"char_f1", .8, "PASS"}, {"not_implemented", 0, "NOT_MEASURED"}} {
		th := Threshold{ID: "T", Dataset: g.Dataset, Category: g.Category, Language: g.Language, EntityType: "Email", Metric: tc.metric, Operator: ">=", Bound: &tc.bound}
		got := EvaluateThresholds([]Threshold{th}, []Group{g})
		if got[0].Status != tc.status {
			t.Fatal(tc, got)
		}
	}
}
func floatPtr(v float64) *float64 { return &v }
func TestPIIAdapterAndPerEntityMetrics(t *testing.T) {
	records := GenerateDev()
	b, _ := json.Marshal(records)
	s := Dataset{Name: "PII-dev", SplitUse: "dev", Category: "category::sensitive-info"}
	items, e := Adapt(bytes.NewReader(b), s, LockedFile{Path: "fake"})
	if e != nil || len(items) != 20 {
		t.Fatal(e)
	}
	item := items[0]
	c := testConfig()
	c.LabelMapping = map[string]string{item.Gold[0].Type: item.Gold[0].Type}
	obs := Observation{Item: item, Result: Result{Decision: "alert", Findings: []Finding{{Category: s.Category, Type: item.Gold[0].Type, Span: item.Gold[0].Span}}}}
	g := Summarize(s, []Observation{obs}, c)
	if len(g) != 1 || g[0].Counts.TP != 1 || *g[0].Entities[item.Gold[0].Type].CharacterF1 != 1 {
		t.Fatal(g)
	}
}
