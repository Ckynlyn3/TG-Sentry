package core

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func outgoingFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCaptureOutgoingFilesSnapshotsReadTools(t *testing.T) {
	dir := t.TempDir()
	path := outgoingFile(t, dir, "note.txt", "customer record "+syntheticID()+"\n")
	for _, key := range []string{"file_path", "path", "filePath"} {
		t.Run(key, func(t *testing.T) {
			files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{key: path}, nil, "not_applicable")
			if status != "complete" || len(files) != 1 || !files[0].Complete || files[0].Content == "" || files[0].SHA256 == "" || files[0].Bytes == 0 || files[0].Path != path {
				t.Fatalf("unexpected snapshot: status=%s files=%+v", status, files)
			}
		})
	}
	// Relative paths resolve against the agent's working directory.
	rel, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": "note.txt"}, nil, "not_applicable")
	if status != "complete" || len(rel) != 1 || rel[0].Path != path {
		t.Fatalf("relative path not resolved: status=%s files=%+v", status, rel)
	}
	// Read.offset/limit select a window, but the whole file is scanned: a
	// beginning-only read must not hide a later identifier.
	tail := outgoingFile(t, dir, "tail.txt", strings.Repeat("a", 40)+syntheticID())
	for _, args := range []map[string]any{
		{"file_path": tail, "offset": 1, "limit": 3},
		{"path": tail, "offset": float64(0), "limit": float64(1)},
	} {
		windowed, windowedStatus := CaptureOutgoingFiles(dir, "Read", args, nil, "not_applicable")
		if windowedStatus != "complete" || len(windowed) != 1 || !strings.Contains(windowed[0].Content, syntheticID()) {
			t.Fatalf("windowed read was truncated: status=%s files=%+v", windowedStatus, windowed)
		}
	}
}

// The tool path is opened exactly as the agent wrote it: trimming would read a
// different (valid) filename. Cleaning would resolve ".."/symlinks differently
// from the native filesystem (review #24 HIGH 1; see the unix test).
func TestCaptureOutgoingFilesOpensLiteralPath(t *testing.T) {
	dir := t.TempDir()
	// A trailing space is a legal POSIX filename byte, not padding to strip.
	spaced := outgoingFile(t, dir, "note.txt ", "padded\n")
	outgoingFile(t, dir, "note.txt", "trimmed\n") // What trimming would read.
	files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": spaced}, nil, "not_applicable")
	if status != "complete" || len(files) != 1 || files[0].Content != "padded\n" {
		t.Fatalf("whitespace-bearing name was rewritten: status=%s files=%+v", status, files)
	}
}

func TestCaptureOutgoingFilesLeavesOtherToolsUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := outgoingFile(t, dir, "note.txt", "hello")
	prior := []ReviewScript{{Path: "/tmp/check.py", Content: "print(1)", Complete: true}}
	for _, tc := range []struct {
		name string
		tool string
		args map[string]any
	}{
		{"bash", "Bash", map[string]any{"command": "python check.py"}},
		{"write", "Write", map[string]any{"file_path": path, "content": "hello"}},
		{"no-path", "Read", map[string]any{"offset": 1}},
		{"empty-path", "Read", map[string]any{"file_path": ""}},
		{"non-string", "Read", map[string]any{"file_path": []any{path}}},
		{"codex", "read_file", map[string]any{"path": path}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, status := CaptureOutgoingFiles(dir, tc.tool, tc.args, prior, "complete")
			if status != "complete" || len(files) != len(prior) || files[0] != prior[0] {
				t.Fatalf("non-applicable tool changed the carrier: status=%s files=%+v", status, files)
			}
			empty, none := CaptureOutgoingFiles(dir, tc.tool, tc.args, nil, "not_applicable")
			if none != "not_applicable" || empty != nil {
				t.Fatalf("non-applicable tool produced a status: %s %+v", none, empty)
			}
		})
	}
}

func TestCaptureOutgoingFilesOversizeIsContentFree(t *testing.T) {
	dir := t.TempDir()
	path := outgoingFile(t, dir, "large.txt", strings.Repeat("x", maxReviewScriptBytes+1))
	files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": path}, nil, "not_applicable")
	if status != "incomplete" || len(files) != 1 || files[0].Content != "" || !files[0].Truncated || files[0].ReadError == "" || files[0].SHA256 != "" {
		t.Fatalf("oversize file was captured: status=%s files=%+v", status, files)
	}
	// The entry keeps its path so a reviewer can see what was refused.
	if files[0].Path != path {
		t.Fatal(files)
	}
	// The known descriptor size is retained: D2 requires size metadata even
	// when the content is refused (review #24 MEDIUM 6).
	if files[0].Bytes != maxReviewScriptBytes+1 {
		t.Fatalf("oversize entry lost its size: %+v", files[0])
	}
}

// A file that grows between fstat and read must not be reported complete with
// only maxReviewScriptBytes+1 bytes: LimitReader returns EOF at its bound, not
// an overflow error (https://pkg.go.dev/io#LimitReader; review #24 HIGH 2).
func TestCaptureOutgoingFilesGrowthAfterStatIsIncomplete(t *testing.T) {
	dir := t.TempDir()
	// Starts inside the limit; grows past it after fstat, before the read.
	path := outgoingFile(t, dir, "growing.txt", strings.Repeat("a", maxReviewScriptBytes-100))
	previous := readOutgoingBytes
	t.Cleanup(func() { readOutgoingBytes = previous })
	readOutgoingBytes = func(f *os.File) ([]byte, error) {
		// Valid UTF-8 throughout: only the length reveals the growth.
		if err := os.WriteFile(path, []byte(strings.Repeat("a", maxReviewScriptBytes+1)), 0600); err != nil {
			return nil, err
		}
		return io.ReadAll(io.LimitReader(f, maxReviewScriptBytes+1))
	}
	files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": path}, nil, "not_applicable")
	if status != "incomplete" || len(files) != 1 || files[0].Content != "" || files[0].SHA256 != "" || files[0].ReadError != outgoingFileGrown {
		t.Fatalf("grown file was marked complete: status=%s files=%+v", status, files)
	}
	// The size the descriptor reported before the read is retained.
	if files[0].Bytes != maxReviewScriptBytes-100 {
		t.Fatalf("size metadata lost: %+v", files[0])
	}
}

// A genuine near-limit file (not a placeholder) goes through the detector and
// is rejected on its identifier (review #24 MEDIUM 5).
func TestOutgoingFileNearLimitScannedThroughDetector(t *testing.T) {
	e := engine(t)
	seen := 0
	e.Settings.BTPII = fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) {
		seen++
		respondID(w, r)
	})
	e.Settings.BTPII.Entities = []string{"CN_ID_CARD"}
	enableSensitiveRule(t, e, "R_PII_ID", "id-number", "reject")
	dir := t.TempDir()
	// Just under the per-file limit, with the identifier in the tail: only a
	// whole-file capture finds it.
	body := strings.Repeat("z", maxReviewScriptBytes-len(syntheticID())-1) + syntheticID()
	path := outgoingFile(t, dir, "near-limit.txt", body)
	files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": path}, nil, "not_applicable")
	if status != "complete" || len(files) != 1 || files[0].Bytes != int64(len(body)) {
		t.Fatalf("near-limit file was not captured: status=%s files=%+v", status, files)
	}
	r, err := e.Submit(ReviewInput{InstanceID: "instance", CallID: "near-limit", ToolName: "Read", Arguments: map[string]any{"file_path": path}, Scripts: files, ScriptCaptureStatus: status})
	if err != nil || r.Decision != "reject" || r.RuleID != "R_PII_ID" || seen == 0 || len(r.Scripts) != 0 {
		t.Fatalf("near-limit identifier was not detected: %+v %v seen=%d", r, err, seen)
	}
}

func TestOutgoingFileGrowthForcesHuman(t *testing.T) {
	e := engine(t)
	dir := t.TempDir()
	path := outgoingFile(t, dir, "growing.txt", strings.Repeat("a", maxReviewScriptBytes-100))
	previous := readOutgoingBytes
	t.Cleanup(func() { readOutgoingBytes = previous })
	readOutgoingBytes = func(f *os.File) ([]byte, error) {
		// Valid UTF-8 throughout: only the length reveals the growth.
		if err := os.WriteFile(path, []byte(strings.Repeat("a", maxReviewScriptBytes+1)), 0600); err != nil {
			return nil, err
		}
		return io.ReadAll(io.LimitReader(f, maxReviewScriptBytes+1))
	}
	files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": path}, nil, "not_applicable")
	r, err := e.Submit(ReviewInput{InstanceID: "instance", CallID: "grown", ToolName: "Read", Arguments: map[string]any{"file_path": path}, Scripts: files, ScriptCaptureStatus: status})
	if err != nil || r.Decision != "pending" || r.ReviewPath != "human" || !r.NeedsHuman {
		t.Fatalf("grown capture was auto-allowed: %+v %v", r, err)
	}
}

func TestFitOutgoingFileSnapshotKeepsTransportBound(t *testing.T) {
	dir := t.TempDir()
	// Within the per-file limit, but with the call's own arguments the review
	// body cannot fit the transport bound, so the content must be dropped.
	path := outgoingFile(t, dir, "edge.txt", strings.Repeat("y", maxReviewScriptBytes))
	args := map[string]any{"file_path": path, "padding": strings.Repeat("p", ToolOutputJSONBytes-maxReviewScriptBytes)}
	files, status := CaptureOutgoingFiles(dir, "Read", args, nil, "not_applicable")
	if status != "complete" || len(files) != 1 || len(files[0].Content) == 0 {
		t.Fatalf("per-file limit alone refused the file: status=%s files=%+v", status, files)
	}
	in := ReviewInput{ToolName: "Read", Arguments: args, Scripts: files, ScriptCaptureStatus: status}
	envelope, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	FitOutgoingFileSnapshot(&in, 0, len(envelope))
	if in.ScriptCaptureStatus != "incomplete" || len(in.Scripts) != 1 || in.Scripts[0].Content != "" || !in.Scripts[0].Truncated || in.Scripts[0].ReadError != OutgoingFileOverEnvelope {
		t.Fatalf("over-bound capture kept content: status=%s files=%+v", in.ScriptCaptureStatus, in.Scripts)
	}
	if b, err := json.Marshal(in); err != nil || len(b) > ToolOutputJSONBytes {
		t.Fatalf("envelope still over the transport bound: %d %v", len(b), err)
	}
	// A script snapshot captured before the outgoing file keeps its retention.
	prior := append([]ReviewScript{{Path: "/tmp/check.py", Content: "print(1)", Complete: true}}, files...)
	kept := ReviewInput{ToolName: "Read", Arguments: args, Scripts: prior, ScriptCaptureStatus: status}
	if b, err := json.Marshal(kept); err != nil {
		t.Fatal(err)
	} else {
		FitOutgoingFileSnapshot(&kept, 1, len(b))
	}
	if kept.Scripts[0].Content != "print(1)" || kept.Scripts[1].Content != "" {
		t.Fatalf("existing script retention changed: %+v", kept.Scripts)
	}
}

func TestCaptureOutgoingFilesRejectsUnreadableInput(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ name, content string }{
		{"invalid-utf8", "\xff\xfe\x00binary"},
		{"nul", "text\x00more"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := outgoingFile(t, dir, tc.name, tc.content)
			files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": path}, nil, "not_applicable")
			if status != "incomplete" || len(files) != 1 || files[0].Content != "" || files[0].ReadError == "" {
				t.Fatalf("non-text file was captured: status=%s files=%+v", status, files)
			}
		})
	}
	// The hook shares the agent's OS privileges, so an absent path has no bytes
	// surface for anyone; the caller's carrier and status stay unchanged.
	missing, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": filepath.Join(dir, "absent.txt")}, nil, "not_applicable")
	if status != "not_applicable" || missing != nil {
		t.Fatalf("missing file changed the carrier: status=%s files=%+v", status, missing)
	}
	directory, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": dir}, nil, "not_applicable")
	if status != "incomplete" || len(directory) != 1 || directory[0].ReadError == "" {
		t.Fatalf("directory was not refused: status=%s files=%+v", status, directory)
	}
}

// The plan's acceptance scenario: an outgoing file with an ID number is blocked
// before dispatch and the stored review omits the whole captured surface.
func TestOutgoingFileSensitiveRejectKeepsNoSnapshot(t *testing.T) {
	e := engine(t)
	seen := 0
	e.Settings.BTPII = fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) {
		seen++
		respondID(w, r)
	})
	e.Settings.BTPII.Entities = []string{"CN_ID_CARD"}
	enableSensitiveRule(t, e, "R_PII_ID", "id-number", "reject")
	dir := t.TempDir()
	path := outgoingFile(t, dir, "record.txt", "客户记录 "+syntheticID()+"\n")
	files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": path}, nil, "not_applicable")
	r, err := e.Submit(ReviewInput{InstanceID: "instance", CallID: "outgoing-reject", ToolName: "Read", Arguments: map[string]any{"file_path": path}, Scripts: files, ScriptCaptureStatus: status})
	if err != nil || r.Decision != "reject" || r.RuleID != "R_PII_ID" || r.Execution != "not_executed" {
		t.Fatalf("outgoing file was not blocked: %+v %v", r, err)
	}
	if seen == 0 {
		t.Fatal("detector was not consulted")
	}
	stored, err := e.Review(r.ID)
	if err != nil || reviewInputState(stored) != ContentPolicyOmitted || len(stored.Scripts) != 0 {
		t.Fatalf("sensitive hit kept a snapshot: %+v %v", stored, err)
	}
	if b, _ := json.Marshal(stored); strings.Contains(string(b), syntheticID()) {
		t.Fatal("identifier retained in the review")
	}
}

// A clean file snapshot keeps the existing retention path and reaches the model
// input carrier; the tool arguments still decide the verdict (builtin A7 read).
func TestOutgoingFileCleanSnapshotRetained(t *testing.T) {
	e := engine(t)
	e.Settings.BTPII = fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`[]`)) })
	e.Settings.BTPII.Entities = []string{"CN_ID_CARD"}
	enableSensitiveRule(t, e, "R_PII_ID", "id-number", "reject")
	dir := t.TempDir()
	path := outgoingFile(t, dir, "clean.txt", "hello\n")
	files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": path}, nil, "not_applicable")
	r, err := e.Submit(ReviewInput{InstanceID: "instance", CallID: "outgoing-clean", ToolName: "Read", Arguments: map[string]any{"file_path": path}, Scripts: files, ScriptCaptureStatus: status})
	if err != nil || r.Decision != "approve" || r.ScriptCaptureStatus != "complete" || len(r.Scripts) != 1 || r.Scripts[0].Content != "hello\n" {
		t.Fatalf("clean snapshot lost: %+v %v", r, err)
	}
	if reviewInputState(r) != ContentCaptured {
		t.Fatal("clean capture was treated as omitted")
	}
	if b, _ := json.Marshal(modelInput(r)); !strings.Contains(string(b), `"scriptFiles"`) || !strings.Contains(string(b), "hello") {
		t.Fatal("clean snapshot is not part of the model carrier")
	}
}

// An incomplete capture cannot be auto-approved; an existing terminal denial
// still stands and an undecided review goes to the model fallback first.
// D6 submission path: an otherwise undecided submission carrying a clean
// captured file reaches the model fallback through Engine.Submit itself. No
// review state is injected: A7 is disabled so the call is undecided, the model
// transport is the only fake, and its verdict must be honored.
func TestOutgoingFileCleanSnapshotReachesModelBySubmit(t *testing.T) {
	e := engine(t)
	a := ruleByID(t, e, "A7")
	a.Enabled = false
	if err := e.SaveRule(testActorContext(), a); err != nil {
		t.Fatal(err)
	}
	var calls int
	var sawContent bool
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	http.DefaultTransport = reviewRoundTrip(func(req *http.Request) (*http.Response, error) {
		calls++
		body, _ := io.ReadAll(req.Body)
		sawContent = sawContent || strings.Contains(string(body), "hello")
		verdict := `{"decision":"approve","comment":"实际操作：读取；成功后的后果：获得信息；命中规则：A7"}`
		payload, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": verdict}}}})
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(payload)))}, nil
	})
	e.Settings.Mode = "model"
	e.Settings.Model = ModelConfig{ProcessingClass: ModelProcessingSelfHosted, Protocol: "openai", BaseURL: "https://fixture.invalid", Model: "fixture", Tested: true}
	dir := t.TempDir()
	path := outgoingFile(t, dir, "clean.txt", "hello\n")
	files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": path}, nil, "not_applicable")
	if status != "complete" {
		t.Fatal(status)
	}
	r, err := e.Submit(ReviewInput{InstanceID: "instance", CallID: "outgoing-clean-model", ToolName: "Read", Arguments: map[string]any{"file_path": path}, Scripts: files, ScriptCaptureStatus: status})
	if err != nil || r.Decision != "pending" || r.ReviewPath != "model" || r.NeedsHuman {
		t.Fatalf("clean submission did not enter the model path: %+v %v", r, err)
	}
	for n := 0; n < 400 && r.Decision == "pending"; n++ {
		time.Sleep(5 * time.Millisecond)
		r, err = e.Review(r.ID)
	}
	if err != nil || r.Decision != "approve" || r.ReviewPath != "model" || r.Execution != "awaiting_execution" {
		t.Fatalf("model verdict was not honored: %+v %v", r, err)
	}
	if calls == 0 || !sawContent {
		t.Fatalf("model fallback was not reached with the capture: calls=%d content=%v", calls, sawContent)
	}
}

func TestOutgoingFileIncompleteKeepsHumanAndDenyPaths(t *testing.T) {
	e := engine(t)
	dir := t.TempDir()
	path := outgoingFile(t, dir, "large.txt", strings.Repeat("x", maxReviewScriptBytes+1))
	files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": path}, nil, "not_applicable")
	if status != "incomplete" {
		t.Fatal(status)
	}
	// A builtin read permit is downgraded to the human path.
	r, err := e.Submit(ReviewInput{InstanceID: "instance", CallID: "outgoing-incomplete", ToolName: "Read", Arguments: map[string]any{"file_path": path}, Scripts: files, ScriptCaptureStatus: status})
	if err != nil || r.Decision != "pending" || r.ReviewPath != "human" || !r.NeedsHuman || !strings.Contains(r.Comment, "文件") {
		t.Fatalf("incomplete capture was auto-allowed: %+v %v", r, err)
	}
	// A deterministic denial is terminal and never gains a model step.
	if err := e.SaveRule(testActorContext(), Rule{ID: "U_OUTGOING_DENY", Name: "deny", Enabled: true, Matcher: "contains", Pattern: "large.txt", Decision: "reject"}); err != nil {
		t.Fatal(err)
	}
	denied, err := e.Submit(ReviewInput{InstanceID: "instance", CallID: "outgoing-denied", ToolName: "Read", Arguments: map[string]any{"file_path": path}, Scripts: files, ScriptCaptureStatus: status})
	if err != nil || denied.Decision != "reject" || denied.RuleID != "U_OUTGOING_DENY" {
		t.Fatalf("terminal denial lost: %+v %v", denied, err)
	}
}

func TestOutgoingFileIncompleteModelFallbackStillForcesHuman(t *testing.T) {
	e := engine(t)
	up := modelApproveServer(t)
	r, err := e.Submit(input("outgoing-model", "fixture_tool", map[string]any{"opaque": "value"}))
	if err != nil || r.Decision != "pending" {
		t.Fatal(r, err)
	}
	// Drive the model stage directly, as the existing independent-review tests do.
	r.NeedsHuman, r.Mode, r.ReviewPath = false, "model", "model"
	r.Scripts = []ReviewScript{{Path: "/tmp/large.bin", ReadError: outgoingFileOverLimit, Truncated: true}}
	r.ScriptCaptureStatus = "incomplete"
	if err = e.put("reviews", r.ID, r); err != nil {
		t.Fatal(err)
	}
	s := e.Settings
	s.Model = ModelConfig{ProcessingClass: ModelProcessingSelfHosted, BaseURL: up, Model: "fixture", Tested: true}
	e.modelReview(r, s)
	stored, err := e.Review(r.ID)
	if err != nil || stored.Decision != "pending" || !stored.NeedsHuman || stored.ReviewPath != "human" || !strings.Contains(stored.Comment, "文件") {
		t.Fatalf("model approval bypassed the incomplete capture: %+v %v", stored, err)
	}
}

// D6: reached by submission, not by hand-injecting the review. An incomplete
// capture is not eligible for the model stage at all, so the model never runs
// and the human path is taken by Submit itself (reviews.go forcedHuman).
func TestOutgoingFileIncompleteModelModeGoesHumanBySubmit(t *testing.T) {
	e := engine(t)
	calls := 0
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	http.DefaultTransport = reviewRoundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("incomplete capture dispatched a model request")
	})
	e.Settings.Mode = "model"
	e.Settings.Model = ModelConfig{ProcessingClass: ModelProcessingSelfHosted, Protocol: "openai", BaseURL: "https://fixture.invalid", Model: "fixture", Tested: true}
	dir := t.TempDir()
	path := outgoingFile(t, dir, "large.txt", strings.Repeat("x", maxReviewScriptBytes+1))
	files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": path}, nil, "not_applicable")
	r, err := e.Submit(ReviewInput{InstanceID: "instance", CallID: "outgoing-model-mode", ToolName: "Read", Arguments: map[string]any{"file_path": path}, Scripts: files, ScriptCaptureStatus: status})
	if err != nil || r.Decision != "pending" || r.ReviewPath != "human" || !r.NeedsHuman {
		t.Fatalf("incomplete capture did not reach the human path: %+v %v", r, err)
	}
	if calls != 0 {
		t.Fatalf("model fallback ran for an incomplete capture: %d", calls)
	}
}

// D6 alert path: an alert-class rule on an incomplete capture cannot be
// auto-approved; it lands in the human queue (reviews.go:249-252).
func TestOutgoingFileIncompleteAlertGoesHuman(t *testing.T) {
	e := engine(t)
	dir := t.TempDir()
	path := outgoingFile(t, dir, "large.txt", strings.Repeat("x", maxReviewScriptBytes+1))
	files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": path}, nil, "not_applicable")
	if err := e.SaveRule(testActorContext(), Rule{ID: "U_OUTGOING_ALERT", Name: "alert", Enabled: true, Matcher: "contains", Pattern: "large.txt", Decision: "alert"}); err != nil {
		t.Fatal(err)
	}
	r, err := e.Submit(ReviewInput{InstanceID: "instance", CallID: "outgoing-alert", ToolName: "Read", Arguments: map[string]any{"file_path": path}, Scripts: files, ScriptCaptureStatus: status})
	if err != nil || r.Decision != "pending" || r.ReviewPath != "human" || !r.NeedsHuman || r.Execution == "awaiting_execution" {
		t.Fatalf("alert on an incomplete capture was auto-allowed: %+v %v", r, err)
	}
	if !strings.Contains(r.Comment, "文件") {
		t.Fatalf("human comment did not explain the capture gap: %q", r.Comment)
	}
}

func enableSensitiveRule(t *testing.T, e *Engine, id, tag, decision string) {
	t.Helper()
	if err := e.SaveRule(testActorContext(), Rule{ID: id, Name: "synthetic " + tag, Enabled: true, Matcher: "btpii", Pattern: tag, Decision: decision}); err != nil {
		t.Fatal(err)
	}
}

// respondID reports the synthetic CN ID wherever it appears in the envelope.
func respondID(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text string `json:"text"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	id := syntheticID()
	i := strings.Index(body.Text, id)
	if i < 0 {
		w.Write([]byte(`[]`))
		return
	}
	start := utf16Length(body.Text[:i])
	json.NewEncoder(w).Encode([]map[string]any{{"entity_type": "CN_ID_CARD", "start": start, "end": start + len(id), "score": 1}})
}

func modelApproveServer(t *testing.T) string {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": `{"decision":"approve","comment":"实际操作：读取；成功后的后果：获得信息；命中规则：A7"}`}}}})
	}))
	t.Cleanup(up.Close)
	return up.URL
}
