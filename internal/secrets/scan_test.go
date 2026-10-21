package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestScanClean(t *testing.T) {
	for _, text := range []string{"", "ordinary tool output", "password=not-a-provider-token"} {
		assertScan(t, text, nil)
	}
}

func TestScanKeywordORAndCase(t *testing.T) {
	// AWS has five alternative keywords; a candidate has only one, never all.
	for _, prefix := range []string{"AKIA", "ASIA", "ABIA", "ACCA", "A3TA"} {
		t.Run(prefix, func(t *testing.T) {
			candidate := syntheticCandidate(t, "aws-access-token", prefix)
			assertScan(t, candidate, []Finding{{RuleID: "aws-access-token", EntityType: "aws-access-token", Span: Span{0, len(candidate)}}})
		})
	}
	// The keyword prefilter ignores case; the rule's regex still controls case.
	candidate := strings.ToLower(syntheticCandidate(t, "aws-access-token", "bare"))
	assertScan(t, candidate, nil)
	key := syntheticCandidate(t, "private-key", "bare")
	key = strings.ReplaceAll(key, "BEGIN", "begin")
	key = strings.ReplaceAll(key, "END", "end")
	key = strings.ReplaceAll(key, "PRIVATE KEY", "private key")
	assertScan(t, key, []Finding{{RuleID: "private-key", EntityType: "private-key", Span: Span{0, utf16Units(key)}}})
}

func TestScanEntropyRejectsEquality(t *testing.T) {
	// Measured synthetic JWT: total 64 ASCII symbols, counts
	// 16,16,8,4,4,4,4,2,2,2,2 => exactly 3 bits (pinned JWT threshold).
	body := strings.Repeat("e", 14) + strings.Repeat("y", 14) + strings.Repeat("Z", 8) + strings.Repeat("A", 4) + strings.Repeat("B", 4) + strings.Repeat("C", 4) + strings.Repeat("D", 4) + "EEFFGG"
	candidate := "ey" + body[:17] + ".ey" + body[17:34] + "." + body[34:]
	if len(candidate) != 64 || fixtureEntropy(candidate) != 3 {
		t.Fatal("fixture must have entropy exactly at upstream threshold")
	}
	assertScan(t, candidate, nil)
	// Moving one occurrence to a new symbol raises entropy above the threshold.
	above := candidate[:len(candidate)-1] + "H"
	if fixtureEntropy(above) <= 3 {
		t.Fatal("control fixture must exceed threshold")
	}
	assertScan(t, above, []Finding{{RuleID: "jwt", EntityType: "jwt", Span: Span{0, len(above)}}})
}

func TestScanAWSAllowlistTargetsExtractedSecret(t *testing.T) {
	candidate := "AKIA" + syntheticText("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 9) + "EXAMPLE"
	if fixtureEntropy(candidate) <= 3 {
		t.Fatal("allowlist fixture must not be rejected by entropy")
	}
	assertScan(t, candidate, nil)
	// The same suffix elsewhere on the line is not an exemption.
	candidate = syntheticCandidate(t, "aws-access-token", "bare")
	assertScan(t, candidate+" EXAMPLE", []Finding{{RuleID: "aws-access-token", EntityType: "aws-access-token", Span: Span{0, len(candidate)}}})
}

func TestScanGlobalAllowlistUsesSecretNotLine(t *testing.T) {
	candidate := syntheticCandidate(t, "github-pat", "bare")
	// Frozen global regex (?i)^true|false|null$ defaults to target=secret.
	// Neither that regex nor a stopword outside the secret suppresses it.
	for _, prefix := range []string{"true ", "abcdefghijklmnopqrstuvwxyz "} {
		assertScan(t, prefix+candidate, []Finding{{RuleID: "github-pat", EntityType: "github-pat", Span: Span{len(prefix), len(prefix + candidate)}}})
	}
	assertScan(t, negativeCandidate(t, "github-pat", "global-stopword"), nil)
}

func TestScanIgnoresInlineGitleaksAllow(t *testing.T) {
	candidate := syntheticCandidate(t, "anthropic-api-key", "bare")
	assertScan(t, candidate+" # gitleaks:allow", []Finding{{RuleID: "anthropic-api-key", EntityType: "anthropic-api-key", Span: Span{0, len(candidate)}}})
}

func TestScanFindsRepeatedCandidates(t *testing.T) {
	candidate := syntheticCandidate(t, "github-pat", "bare")
	prefix := "😀 "
	second := utf16Units(prefix + candidate + "\n")
	assertScan(t, prefix+candidate+"\n"+candidate, []Finding{
		{RuleID: "github-pat", EntityType: "github-pat", Span: Span{utf16Units(prefix), utf16Units(prefix + candidate)}},
		{RuleID: "github-pat", EntityType: "github-pat", Span: Span{second, second + len(candidate)}},
	})
}

func pathDigest(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:])
}

func TestScanTreeKeysValuesAndDigestOnlyLocations(t *testing.T) {
	candidate := syntheticCandidate(t, "github-pat", "bare")
	for _, value := range []any{nil, candidate} {
		input := map[string]any{candidate: value, "outer": []any{false, "😀 " + candidate, 7}}
		before, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		got, status := ScanTree(context.Background(), input, "tool_input")
		want := []Leaf{
			{Finding: Finding{RuleID: "github-pat", EntityType: "github-pat", Span: Span{0, len(candidate)}}, Surface: "tool_input", Kind: "key", Path: candidate, FieldDigest: pathDigest(candidate)},
			{Finding: Finding{RuleID: "github-pat", EntityType: "github-pat", Span: Span{3, 3 + len(candidate)}}, Surface: "tool_input", Kind: "value", Path: "outer.1", FieldDigest: pathDigest("outer.1")},
		}
		if value != nil {
			want = append(want, Leaf{Finding: Finding{RuleID: "github-pat", EntityType: "github-pat", Span: Span{0, len(candidate)}}, Surface: "tool_input", Kind: "value", Path: candidate, FieldDigest: pathDigest(candidate)})
		}
		if status != Complete || len(got) != len(want) {
			t.Fatalf("tree completion/count mismatch: status=%v count=%d", status, len(got))
		}
		sort.Slice(got, func(i, j int) bool { return got[i].Path+got[i].Kind < got[j].Path+got[j].Kind })
		sort.Slice(want, func(i, j int) bool { return want[i].Path+want[i].Kind < want[j].Path+want[j].Kind })
		if !reflect.DeepEqual(got, want) {
			t.Fatal("tree rule, surface, key/value, path digest or original-leaf span mismatch")
		}
		encoded, err := json.Marshal(got)
		if err != nil || strings.Contains(string(encoded), candidate) {
			t.Fatal("tree findings serialized candidate or cleartext path")
		}
		after, err := json.Marshal(input)
		if err != nil || string(before) != string(after) {
			t.Fatal("scan mutated the original tree")
		}
	}
}

func TestScanTreeRootStringAndCleanScalars(t *testing.T) {
	candidate := syntheticCandidate(t, "gitlab-pat", "bare")
	got, status := ScanTree(context.Background(), candidate, "tool_result")
	if status != Complete || len(got) != 1 {
		t.Fatal("root string was not scanned")
	}
	if got[0].Kind != "value" || got[0].Surface != "tool_result" || got[0].Path != "" || got[0].FieldDigest != pathDigest("") {
		t.Fatal("root string location mismatch")
	}
	for _, v := range []any{nil, 1, true, map[string]any{}, []any{false, "clean"}} {
		got, status := ScanTree(context.Background(), v, "tool_input")
		if status != Complete || len(got) != 0 {
			t.Fatal("clean tree is not complete and empty")
		}
	}
}

// Cancel deterministically at an Err checkpoint, not on a timing race.
type checkpointContext struct {
	context.Context
	cancel context.CancelFunc
	checks int
	at     int
}

func (c *checkpointContext) Err() error {
	c.checks++
	if c.checks == c.at {
		c.cancel()
	}
	return c.Context.Err()
}

func TestScanCancellationDiscardsFindings(t *testing.T) {
	candidate := syntheticCandidate(t, "aws-access-token", "bare") + " " + syntheticCandidate(t, "github-pat", "bare")
	// Nine rules plus entry and final checkpoints: exercise cancellation after
	// completed rule work as well as before/between rules (plan §3.2).
	for _, at := range []int{1, 2, 11} {
		base, cancel := context.WithCancel(context.Background())
		ctx := &checkpointContext{Context: base, cancel: cancel, at: at}
		got, status := Scan(ctx, candidate)
		cancel()
		if ctx.checks < at || status != Interrupted || len(got) != 0 {
			t.Fatal("cancellation checkpoint was not honored or partial findings escaped")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, status := Scan(ctx, candidate)
	if status != Interrupted || len(got) != 0 {
		t.Fatal("pre-cancelled scan reported clean or retained findings")
	}
	leaves, status := ScanTree(ctx, map[string]any{candidate: candidate}, "tool_input")
	if status != Interrupted || len(leaves) != 0 {
		t.Fatal("cancelled tree reported clean or retained findings")
	}
}

func TestFindingJSONContainsOnlyLocationMetadata(t *testing.T) {
	candidate := syntheticCandidate(t, "github-pat", "bare")
	leaf := Leaf{Finding: Finding{RuleID: "github-pat", EntityType: "github-pat", Span: Span{0, len(candidate)}}, Surface: "tool_input", Kind: "key", Path: candidate, FieldDigest: pathDigest(candidate)}
	b, err := json.Marshal(leaf)
	if err != nil || strings.Contains(string(b), candidate) {
		t.Fatal("location JSON leaked original material")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	want := []string{"entity_type", "field_digest", "kind", "span", "surface"}
	var keys []string
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if !reflect.DeepEqual(keys, want) {
		t.Fatal("location JSON contains missing or non-location fields")
	}
}

func TestSecretsPackageHasNoHTTPImport(t *testing.T) {
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".go") || strings.HasSuffix(file.Name(), "_test.go") {
			continue
		}
		node, err := parser.ParseFile(token.NewFileSet(), file.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range node.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || path == "net/http" || strings.HasPrefix(path, "net/http/") {
				t.Fatal("secrets package imports HTTP code")
			}
		}
	}
}
