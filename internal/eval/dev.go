package eval

import (
	"aegishook/internal/core"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DevOptions deliberately has no manifest, lock, seed or dataset path. This
// entry point cannot read acquisition inputs or relax the frozen Run gates.
type DevOptions struct {
	Root, Config, Out string
}

// RunDev exercises native reviews on GenerateDev only. It is an adaptive dev
// smoke run, never an acceptance verdict. CheckGit is diagnostic only here;
// frozen Run and production manifest admission remain unchanged.
func RunDev(ctx context.Context, o DevOptions) (rep Report, runErr error) {
	rep = Report{Version: SchemaVersion, Tag: "dev-only", DevOnly: true, StartedAt: time.Now().UTC(), Nondeterministic: true, Exposure: map[string]int{}, Digests: map[string]string{}}
	var c FrozenConfig
	path := o.Config
	if !filepath.IsAbs(path) {
		path = filepath.Join(o.Root, path)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return rep, errors.New("cannot open dev configuration")
	}
	if err := Decode(bytes.NewReader(payload), &c); err != nil {
		return rep, err
	}
	if len(c.Thresholds) != 0 {
		return rep, errors.New("dev-only configuration must not contain acceptance thresholds")
	}
	// CLI has no independently observed component digests. As in frozen Run,
	// never copy configured digests into the live side of the validation.
	if err := c.Validate(nil); err != nil {
		return rep, err
	}
	hash, _, _ := hashReader(bytes.NewReader(payload))
	rep.Digests["config"] = hash
	// Git is provenance only in dev mode, not an admission requirement.
	rep.HEAD = "unknown"
	if head, err := validationGit(o.Root, "rev-parse", "HEAD"); err == nil {
		rep.HEAD = strings.TrimSpace(string(head))
	}
	rep.DevGitCheck = "PASS"
	if _, err := CheckGit(o.Root); err != nil {
		rep.DevGitCheck = err.Error()
	}
	rep.Hardware = map[string]any{"goos": runtime.GOOS, "goarch": runtime.GOARCH, "go_version": runtime.Version(), "cpu_count": runtime.NumCPU(), "gomaxprocs": runtime.GOMAXPROCS(0), "host_class": c.HostClass}
	// Runner/report metadata only: dev mode never admits a manifest selector.
	s := Dataset{Name: "PII-dev", SplitUse: "dev", Mode: "full-path", Category: "category::prompt-attack"}
	generated := GenerateDev()
	rep.Digests["fixtures"] = Digest(generated)
	if err := os.Mkdir(o.Out, 0700); err != nil {
		return rep, errors.New("output directory must be new before scoring")
	}
	e, cleanup, err := OpenIsolated(c, "")
	if err != nil {
		return rep, err
	}
	defer func() { runErr = errors.Join(runErr, cleanup()) }()
	rows := []Observation{}
	for _, item := range devReviewItems(generated) {
		obs, err := observe(ctx, s, item, c, e, nil)
		if err != nil {
			return rep, err
		}
		rows = append(rows, obs)
	}
	rep.Exposure[s.Name] = 1
	rep.Groups = Summarize(s, rows, c)
	rep.FinishedAt = time.Now().UTC()
	return rep, writeReportFiles(o.Out, rep, rows)
}

func devReviewItems(rows []PIIRecord) []Item {
	items := make([]Item, 0, len(rows))
	for _, row := range rows {
		// Existing #21/#26 integration projects every GenerateDev baseline into a
		// prompt_turn (full_path_prompt_attack_test.go). Original fixture surfaces
		// are source provenance only, not a tool-result lifecycle claim. These PII
		// fixtures are benign for prompt-attack; entity labels are not PA labels.
		in := core.ReviewInput{ToolName: "prompt_turn", Arguments: map[string]any{}, UserMessage: row.Text}
		items = append(items, Item{ID: row.ID, Input: Input{Text: row.Text, Language: row.Language, Surface: "prompt", Tenant: "eval"}, Review: &in, Seed: row.Seed})
	}
	return items
}
