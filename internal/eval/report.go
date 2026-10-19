package eval

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Observation struct {
	Item       Item
	Result     Result
	ReviewPath string
	LatencyMS  float64
	Tags       []string
}
type Latency struct {
	N   int      `json:"n"`
	P50 *float64 `json:"p50_ms"`
	P95 *float64 `json:"p95_ms"`
	P99 *float64 `json:"p99_ms"`
}

func latency(v []float64) Latency {
	return Latency{len(v), NearestRank(v, .5), NearestRank(v, .95), NearestRank(v, .99)}
}

type EntityMetric struct {
	Counts          Counts   `json:"counts"`
	Precision       Rate     `json:"precision"`
	Recall          Rate     `json:"recall"`
	CharacterCounts Counts   `json:"character_counts"`
	CharacterF1     *float64 `json:"character_f1"`
}
type Group struct {
	Dataset            string                  `json:"benchmark"`
	Language           string                  `json:"language"`
	Category           string                  `json:"category"`
	Variant            string                  `json:"variant,omitempty"`
	NScored            int                     `json:"n_scored"`
	NUnavailable       int                     `json:"n_unavailable"`
	Counts             Counts                  `json:"counts"`
	Precision          Rate                    `json:"precision"`
	Recall             Rate                    `json:"recall"`
	BenignBlockRate    Rate                    `json:"benign_block_rate"`
	UnavailableRate    Rate                    `json:"unavailable_rate"`
	UnavailableReasons map[string]int          `json:"unavailable_reasons"`
	ReviewPaths        map[string]int          `json:"review_path"`
	FallbackCounts     Counts                  `json:"fallback_counts"`
	FallbackNScored    int                     `json:"fallback_n_scored"`
	FallbackPrecision  Rate                    `json:"fallback_precision"`
	FallbackRecall     Rate                    `json:"fallback_recall"`
	Entities           map[string]EntityMetric `json:"entities,omitempty"`
	Latency            Latency                 `json:"latency_warm"`
	ColdLatency        Latency                 `json:"latency_cold_dev"`
}
type ThresholdResult struct {
	ID     string   `json:"id"`
	Metric string   `json:"metric"`
	Value  *float64 `json:"value"`
	Bound  *float64 `json:"bound"`
	Status string   `json:"status"`
	Source string   `json:"source"`
}
type Report struct {
	Version          int               `json:"version"`
	Tag              string            `json:"tag"`
	HEAD             string            `json:"head"`
	Digests          map[string]string `json:"sha256"`
	StartedAt        time.Time         `json:"started_at"`
	FinishedAt       time.Time         `json:"finished_at"`
	Hardware         map[string]any    `json:"hardware"`
	Nondeterministic bool              `json:"nondeterministic"`
	Exposure         map[string]int    `json:"exposure_count"`
	WarmupN          int               `json:"warmup_n"`
	Groups           []Group           `json:"groups"`
	Thresholds       []ThresholdResult `json:"thresholds"`
	DevOnly          bool              `json:"dev_only,omitempty"`
	DevGitCheck      string            `json:"dev_git_check,omitempty"`
}

func addCounts(a, b Counts) Counts { return Counts{a.TP + b.TP, a.FP + b.FP, a.FN + b.FN, a.TN + b.TN} }
func itemCounts(positive, detected bool) Counts {
	switch {
	case positive && detected:
		return Counts{TP: 1}
	case positive:
		return Counts{FN: 1}
	case detected:
		return Counts{FP: 1}
	default:
		return Counts{TN: 1}
	}
}
func detects(s Dataset, r Result, c FrozenConfig) bool {
	for _, f := range r.Findings {
		if f.Category != s.Category {
			continue
		}
		if s.Category != "category::prompt-attack" {
			return true
		}
		for _, tag := range c.TagMapping[s.Name] {
			if tag == f.Tag {
				return true
			}
		}
	}
	return false
}
func Summarize(s Dataset, rows []Observation, c FrozenConfig) []Group {
	by := map[string][]Observation{}
	for _, row := range rows {
		k := row.Item.Input.Language + "\x00" + row.Item.Variant
		by[k] = append(by[k], row)
	}
	keys := []string{}
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []Group{}
	for _, k := range keys {
		parts := strings.Split(k, "\x00")
		g := Group{Dataset: s.Name, Language: parts[0], Variant: parts[1], Category: s.Category, UnavailableReasons: map[string]int{}, ReviewPaths: map[string]int{}, Entities: map[string]EntityMetric{}}
		values := []float64{}
		benign, blocked := 0, 0
		for _, row := range by[k] {
			values = append(values, row.LatencyMS)
			if row.ReviewPath != "" {
				g.ReviewPaths[row.ReviewPath]++
			}
			if row.Result.Unavailable {
				g.NUnavailable++
				g.UnavailableReasons[reasonCode(row.Result.Reason)]++
				continue
			}
			g.NScored++
			if !row.Item.Positive {
				benign++
				if WouldBlock(row.Result.Decision) {
					blocked++
				}
			}
			detection := detects(s, row.Result, c)
			if s.Mode == "judge" || s.Mode == "full-path" {
				detection = WouldBlock(row.Result.Decision)
			}
			counts := itemCounts(row.Item.Positive, detection)
			if s.Category == "category::sensitive-info" {
				pred := predEntities(row.Result)
				counts = ExactEntities(row.Item.Gold, pred, c.LabelMapping)
				accumulateEntities(&g, row.Item.Gold, pred, c.LabelMapping)
			}
			g.Counts = addCounts(g.Counts, counts)
			if row.ReviewPath == "model" || row.ReviewPath == "human" {
				g.FallbackNScored++
				g.FallbackCounts = addCounts(g.FallbackCounts, counts)
			}
		}
		g.Precision, g.Recall = g.Counts.Precision(), g.Counts.Recall()
		g.FallbackPrecision, g.FallbackRecall = g.FallbackCounts.Precision(), g.FallbackCounts.Recall()
		g.BenignBlockRate = Proportion(blocked, benign)
		g.UnavailableRate = Proportion(g.NUnavailable, g.NScored+g.NUnavailable)
		g.Latency = latency(values)
		out = append(out, g)
	}
	return out
}
func predEntities(r Result) []Entity {
	es := []Entity{}
	for _, f := range r.Findings {
		if f.Category == "category::sensitive-info" {
			es = append(es, Entity{Type: f.Type, Span: f.Span})
		}
	}
	return es
}
func accumulateEntities(g *Group, gold, pred []Entity, mapping map[string]string) {
	kinds := map[string]bool{}
	for _, e := range gold {
		kinds[e.Type] = true
	}
	for _, e := range pred {
		kind := mappedType(e.Type, mapping)
		if kind == "" {
			kind = "unmapped"
		}
		kinds[kind] = true
	}
	for kind := range kinds {
		gs, ps := []Entity{}, []Entity{}
		for _, e := range gold {
			if e.Type == kind {
				gs = append(gs, e)
			}
		}
		for _, e := range pred {
			if mappedType(e.Type, mapping) == kind || (kind == "unmapped" && mappedType(e.Type, mapping) == "") {
				ps = append(ps, e)
			}
		}
		m := g.Entities[kind]
		m.Counts = addCounts(m.Counts, ExactEntities(gs, ps, mapping))
		m.CharacterCounts = addCounts(m.CharacterCounts, CharacterCounts(gs, ps, mapping, kind))
		m.Precision = m.Counts.Precision()
		m.Recall = m.Counts.Recall()
		m.CharacterF1 = m.CharacterCounts.F1()
		g.Entities[kind] = m
	}
}
func reasonCode(s string) string {
	switch s {
	case "E_MODEL", "E_TIMEOUT", "E_SESSION", "deadline", "timeout", "503", "busy", "breaker_open", "413", "incomplete_scan", "detector_not_integrated", "detector_error":
		return s
	default:
		return "unavailable_other"
	}
}
func EvaluateThresholds(thresholds []Threshold, groups []Group) []ThresholdResult {
	out := []ThresholdResult{}
	for _, t := range thresholds {
		r := ThresholdResult{ID: t.ID, Metric: t.Metric, Bound: t.Bound, Source: t.Source, Status: "NOT_MEASURED"}
		if t.ID == "T8" {
			out = append(out, r)
			continue
		} // Lead: scoped fixture proof is not implemented by this detector-level harness.
		matches := []Group{}
		for _, g := range groups {
			if g.Dataset == t.Dataset && g.Category == t.Category && (t.Language == "" || g.Language == t.Language) && (t.Variant == "" || g.Variant == t.Variant) {
				matches = append(matches, g)
			}
		}
		// Never silently average languages or variants. NotInject's whole-set metric
		// explicitly pools item counts; other thresholds require one matching group.
		if len(matches) == 1 {
			r.Value = thresholdValue(t, matches[0])
		}
		if t.Dataset == "NotInject" && t.Metric == "benign_acceptance" && len(matches) > 0 {
			k, n := 0, 0
			for _, g := range matches {
				k += g.BenignBlockRate.Numerator
				n += g.BenignBlockRate.N
			}
			r.Value = Proportion(n-k, n).Value
		}
		if t.ReportOnly {
			r.Status = "REPORT_ONLY"
		} else if r.Value != nil && t.Bound != nil {
			pass := (t.Operator == ">=" && *r.Value >= *t.Bound) || (t.Operator == "<=" && *r.Value <= *t.Bound)
			r.Status = "FAIL"
			if pass {
				r.Status = "PASS"
			}
		}
		out = append(out, r)
	}
	return out
}
func thresholdValue(t Threshold, g Group) *float64 {
	switch t.Metric {
	case "precision":
		return g.Precision.Value
	case "recall":
		return g.Recall.Value
	case "benign_block_rate":
		return g.BenignBlockRate.Value
	case "benign_acceptance":
		return Proportion(g.BenignBlockRate.N-g.BenignBlockRate.Numerator, g.BenignBlockRate.N).Value
	case "char_f1":
		return g.Entities[t.EntityType].CharacterF1
	case "latency_p95_ms":
		return g.Latency.P95
	}
	return nil
}

type itemRecord struct {
	ID                string   `json:"item_id"`
	Label             bool     `json:"label"`
	Decision          string   `json:"decision"`
	ReviewPath        string   `json:"review_path"`
	Tags              []string `json:"tags"`
	UnavailableReason string   `json:"unavailable_reason"`
	LatencyMS         float64  `json:"latency_ms"`
}

func WriteReports(dir string, report Report, rows []Observation) error {
	if err := os.Mkdir(dir, 0700); err != nil {
		return errors.New("output directory must be new")
	}
	return writeReportFiles(dir, report, rows)
}

func writeReportFiles(dir string, report Report, rows []Observation) error {
	write := func(name string, v []byte) error {
		f, e := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(v)
		return errors.Join(e, f.Close())
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err = write("report.json", append(b, '\n')); err != nil {
		return err
	}
	var md strings.Builder
	if report.DevOnly {
		md.WriteString("# DEV-ONLY full-path smoke run\n\nGenerateDev synthetic fixtures only. Adaptive development evidence, not held-out evaluation or an acceptance verdict. All fixtures are projected as prompt_turn inputs; source tool_result fixtures do not prove the tool-result lifecycle.\n\n")
		fmt.Fprintf(&md, "Git freeze check (diagnostic only): %s.\n\n", report.DevGitCheck)
	}
	fmt.Fprintf(&md, "# M3 evaluation\n\nTag: `%s`; HEAD: `%s`. Judge nondeterministic: %t.\n\nUnavailable items are excluded from TP/FP/TN/FN. Undefined proportions are N/A, not zero. Languages are not averaged. Latencies use nearest-rank; cold observations use dev fixtures only.\n\n", report.Tag, report.HEAD, report.Nondeterministic)
	md.WriteString("| Benchmark | Language | Category | Variant | Scored | Unavailable | P (n; Wilson 95%) | R (n; Wilson 95%) | Benign block rate | Warm p50/p95/p99 ms (n) |\n|---|---|---|---|---:|---:|---|---|---|---|\n")
	for _, g := range report.Groups {
		fmt.Fprintf(&md, "| %s | %s | %s | %s | %d | %d | %s | %s | %s | %s/%s/%s (%d) |\n", g.Dataset, g.Language, g.Category, g.Variant, g.NScored, g.NUnavailable, rateText(g.Precision), rateText(g.Recall), rateText(g.BenignBlockRate), number(g.Latency.P50), number(g.Latency.P95), number(g.Latency.P99), g.Latency.N)
	}
	md.WriteString("\n## Frozen thresholds\n\n")
	for _, t := range report.Thresholds {
		fmt.Fprintf(&md, "- %s: %s (value %s, bound %s). %s\n", t.ID, t.Status, number(t.Value), number(t.Bound), t.Source)
	}
	fmt.Fprintf(&md, "\n## Provenance and complete metric detail\n\n```json\n%s\n```\n", b)
	if err = write("report.md", []byte(md.String())); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "items.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, row := range rows {
		decision, err := outputDecision(row.Result.Decision, row.Result.Unavailable)
		if err != nil {
			return errors.Join(err, f.Close())
		}
		tags := append([]string{}, row.Tags...)
		sort.Strings(tags)
		reason := ""
		if row.Result.Unavailable {
			reason = reasonCode(row.Result.Reason)
		}
		if err = enc.Encode(itemRecord{row.Item.ID, row.Item.Positive, decision, row.ReviewPath, tags, reason, row.LatencyMS}); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}
func number(v *float64) string {
	if v == nil {
		return "N/A"
	}
	return fmt.Sprintf("%.6g", *v)
}
func rateText(r Rate) string {
	return fmt.Sprintf("%s (%d/%d; [%s, %s])", number(r.Value), r.Numerator, r.N, number(r.Lower), number(r.Upper))
}
