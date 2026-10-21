package server

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func exportServer(t *testing.T) (*core.Engine, http.Handler, *http.Cookie) {
	t.Helper()
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	s := New(e, fstest.MapFS{}, "export-admin", "export-hook", t.TempDir())
	h := s.Handler()
	return e, h, rbacCookie(s, "human", core.RoleAdmin)
}

func insertExportRow(t *testing.T, e *core.Engine, id string, events any) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"events": events, "detail": "admin-detail-canary"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = teststore.Admin(t, e.DB).Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES('default','audit',$1,$2)", id, string(raw)); err != nil {
		t.Fatal(err)
	}
}

func exportRequest(h http.Handler, cookie *http.Cookie, path, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "http://127.0.0.1"+path, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	r.Header.Set("Authorization", auth)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestEventExportRoundTrip(t *testing.T) {
	e, h, cookie := exportServer(t)
	if err := e.Register(core.Instance{ID: "fixture", Agent: "claude", SessionID: "session", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Submit(core.ReviewInput{InstanceID: "fixture", CallID: "export-call", ToolName: "Bash", Arguments: map[string]any{"command": "redis-cli FLUSHALL"}}); err != nil {
		t.Fatal(err)
	}
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"risk-events", "audit"} {
		eventType := "tg.sentry.risk.v1"
		if kind == "audit" {
			eventType = "tg.sentry.audit.v1"
		}
		expected := map[string]core.Event{}
		for _, audit := range audits {
			for _, event := range audit.Events {
				if event.Type == eventType {
					expected[event.ID] = event
				}
			}
		}
		if len(expected) == 0 {
			t.Fatal("fixture missing", kind)
		}
		for _, format := range []string{"json", "jsonl"} {
			w := exportRequest(h, cookie, "/api/v1/"+kind+"/export?format="+format, "")
			if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment;") || strings.Contains(w.Body.String(), "admin-detail-canary") {
				t.Fatal(w.Code, w.Body.String())
			}
			var events []core.Event
			if format == "json" {
				if w.Header().Get("Content-Type") != "application/cloudevents-batch+json" {
					t.Fatal(w.Header())
				}
				if err = json.Unmarshal(w.Body.Bytes(), &events); err != nil {
					t.Fatal(err)
				}
			} else {
				if w.Header().Get("Content-Type") != "application/x-ndjson" {
					t.Fatal(w.Header())
				}
				scanner := bufio.NewScanner(w.Body)
				for scanner.Scan() {
					var event core.Event
					if err = json.Unmarshal(scanner.Bytes(), &event); err != nil {
						t.Fatal(err)
					}
					events = append(events, event)
				}
				if err = scanner.Err(); err != nil {
					t.Fatal(err)
				}
			}
			got := map[string]core.Event{}
			for _, event := range events {
				got[event.ID] = event
			}
			if len(events) != len(expected) || !reflect.DeepEqual(got, expected) {
				t.Fatalf("%s/%s parity lost: %+v want %+v", kind, format, got, expected)
			}
		}
	}
}

func TestEventExportAuthValidationAndFailures(t *testing.T) {
	e, h, cookie := exportServer(t)
	for _, kind := range []string{"risk-events", "audit"} {
		path := "/api/v1/" + kind + "/export"
		for _, tc := range []struct {
			auth   string
			status int
		}{{"", 401}, {"Bearer export-hook", 403}, {"Bearer export-admin", 403}} {
			if w := exportRequest(h, nil, path, tc.auth); w.Code != tc.status {
				t.Fatal(path, tc, w.Code)
			}
		}
		for _, query := range []string{"?format=xml", "?severity=invalid", "?category=invalid", "?start=invalid", "?end=invalid", "?start=2026-10-20T00:00:00Z&end=2026-10-19T00:00:00Z"} {
			if w := exportRequest(h, cookie, path+query, ""); w.Code != 400 || !strings.Contains(w.Body.String(), `"error"`) {
				t.Fatal(query, w.Code, w.Body.String())
			}
		}
		for _, format := range []string{"json", "jsonl", "csv"} {
			w := exportRequest(h, cookie, path+"?format="+format, "")
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			if format == "json" && strings.TrimSpace(w.Body.String()) != "[]" {
				t.Fatal(w.Body.String())
			}
			if format == "jsonl" && w.Body.Len() != 0 {
				t.Fatal(w.Body.String())
			}
			if format == "csv" {
				records, err := csv.NewReader(w.Body).ReadAll()
				if err != nil || len(records) != 1 {
					t.Fatal(records, err)
				}
			}
		}
	}
	if err := e.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if w := exportRequest(h, cookie, "/api/v1/audit/export", ""); w.Code != 500 || strings.Contains(w.Body.String(), "sql") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestEventExportCSVProjectionAndHostileCells(t *testing.T) {
	e, h, cookie := exportServer(t)
	var events []map[string]any
	for i, cell := range []string{"normal", "=1+2", "+cmd", "-1", "@SUM(A1)", "\t=cmd", "\r=cmd", "\n=cmd", "＝cmd", "＋cmd", "－cmd", "＠cmd", "comma,quote\"line\r\nvalue", " =cmd", "\"=cmd", "{\"a\":\"=cmd\"}"} {
		events = append(events, map[string]any{"specversion": "1.0", "id": cell, "source": "urn:fixture", "type": "tg.sentry.risk.v1", "time": "2026-10-19T00:00:00Z", "datacontenttype": "application/json", "data": map[string]any{"category_uid": 2, "class_uid": 2004, "activity_id": 1, "type_uid": 200401, "severity_id": 4, "time": 1792368000000, "actor": map[string]any{"app_uid": "agent"}, "metadata": map[string]any{"uid": fmt.Sprint(i)}, "finding_info": map[string]any{"uid": "finding", "types": []string{"category::behavior"}}, "unmapped": map[string]any{"tg_sentry": map[string]any{"value": 9007199254740993}}}})
	}
	insertExportRow(t, e, "fixture", events)
	w := exportRequest(h, cookie, "/api/v1/risk-events/export?format=csv&severity=high&category=category::behavior&agent=agent&start=2026-10-19T00:00:00Z&end=2026-10-19T00:00:00Z", "")
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/csv; charset=utf-8" {
		t.Fatal(w.Code, w.Header(), w.Body.String())
	}
	if !strings.HasSuffix(w.Body.String(), "\r\n") {
		t.Fatal("not RFC4180 record endings")
	}
	records, err := csv.NewReader(w.Body).ReadAll()
	if err != nil || len(records) != len(events)+1 {
		t.Fatal(len(records), err)
	}
	for i, record := range records[1:] {
		for j, column := range records[0] {
			parts := strings.SplitN(column, ".", 2)
			value := events[i][parts[0]]
			if len(parts) == 2 {
				value = value.(map[string]any)[parts[1]]
			}
			expected := ""
			if value != nil {
				if text, ok := value.(string); ok {
					expected = text
				} else {
					raw, _ := json.Marshal(value)
					expected = string(raw)
				}
			}
			if expected != "" && strings.ContainsRune("=+-@\t\r\n＝＋－＠", []rune(expected)[0]) {
				expected = "'" + expected
			}
			// encoding/csv readers normalize quoted CRLF to LF.
			expected = strings.ReplaceAll(expected, "\r\n", "\n")
			if record[j] != expected {
				t.Fatalf("row %d column %s got %q want %q", i, column, record[j], expected)
			}
		}
	}
	for _, query := range []string{"agent=missing", "severity=low", "category=category::prompt-attack", "start=2026-10-20T00:00:00Z", "end=2026-10-18T00:00:00Z"} {
		if w := exportRequest(h, cookie, "/api/v1/risk-events/export?"+query, ""); strings.TrimSpace(w.Body.String()) != "[]" {
			t.Fatal(query, w.Body.String())
		}
	}
}

type exportFlushWriter struct {
	*httptest.ResponseRecorder
	flushes     int
	beforeFlush func()
}

func (w *exportFlushWriter) Flush() {
	w.flushes++
	if w.beforeFlush != nil {
		w.beforeFlush()
	}
	w.ResponseRecorder.Flush()
}

func TestEventExportLargeIncrementalFlush(t *testing.T) {
	e, h, cookie := exportServer(t)
	// More than two store batches (the existing list page ceiling is 100).
	const count = 201
	for i := 0; i < count; i++ {
		insertExportRow(t, e, fmt.Sprintf("row-%03d", i), []map[string]any{{"type": "tg.sentry.audit.v1", "id": fmt.Sprint(i), "data": map[string]any{"extension": 9007199254740993}}})
	}
	for _, format := range []string{"json", "jsonl", "csv"} {
		w := &exportFlushWriter{ResponseRecorder: httptest.NewRecorder()}
		w.beforeFlush = func() {
			if e.DB.Stats().InUse != 0 {
				t.Fatal("store connection held while flushing")
			}
		}
		r := httptest.NewRequest("GET", "http://127.0.0.1/api/v1/audit/export?format="+format, nil)
		r.AddCookie(cookie)
		h.ServeHTTP(w, r)
		if w.Code != 200 || w.flushes < count {
			t.Fatal(format, w.Code, w.flushes)
		}
		if format != "csv" && !strings.Contains(w.Body.String(), "9007199254740993") {
			t.Fatal("JSON number lost precision")
		}
	}
}

func TestEventExportLateFailureAborts(t *testing.T) {
	e, h, cookie := exportServer(t)
	insertExportRow(t, e, "a", []map[string]any{{"type": "tg.sentry.audit.v1", "id": "first"}})
	insertExportRow(t, e, "z", "corrupt-events")
	w := &exportFlushWriter{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest("GET", "http://127.0.0.1/api/v1/audit/export", nil)
	r.AddCookie(cookie)
	defer func() {
		if got := recover(); got != http.ErrAbortHandler {
			t.Fatalf("got %v, wanted stream abort", got)
		}
		if w.flushes == 0 || strings.Contains(w.Body.String(), `"error"`) {
			t.Fatal("not incremental or appended error", w.Body.String())
		}
	}()
	h.ServeHTTP(w, r)
}

func TestEventExportRejectsZeroTime(t *testing.T) {
	_, h, cookie := exportServer(t)
	for _, query := range []string{"start=0001-01-01T00:00:00Z", "end=0001-01-01T00:00:00Z"} {
		if w := exportRequest(h, cookie, "/api/v1/audit/export?"+query, ""); w.Code != 400 {
			t.Fatal(query, w.Code)
		}
	}
}

type exportFaultWriter struct {
	header        http.Header
	calls, failAt int
	flushErr      error
}

func (w *exportFaultWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *exportFaultWriter) WriteHeader(int) {}
func (w *exportFaultWriter) Write(b []byte) (int, error) {
	w.calls++
	if w.calls == w.failAt {
		return 0, io.ErrClosedPipe
	}
	return len(b), nil
}
func (w *exportFaultWriter) FlushError() error { return w.flushErr }

func TestEventExportWriterFailures(t *testing.T) {
	event := json.RawMessage(`{"type":"tg.sentry.audit.v1","id":"fixture","data":{}}`)
	for _, format := range []string{"json", "jsonl", "csv"} {
		for failAt := 1; failAt <= 4; failAt++ {
			w := &exportFaultWriter{failAt: failAt}
			out := eventExportWriter{w: w, format: format, name: "audit"}
			err := out.write(event)
			if err == nil {
				err = out.write(event)
			}
			if w.calls >= failAt && !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal(format, failAt, w.calls, err)
			}
		}
		out := eventExportWriter{w: &exportFaultWriter{flushErr: io.ErrClosedPipe}, format: format, name: "audit"}
		if err := out.write(event); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(format, err)
		}
	}
	for failAt := 1; failAt <= 2; failAt++ {
		out := eventExportWriter{w: &exportFaultWriter{failAt: failAt}, format: "json", name: "audit"}
		if err := out.finish(); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(failAt, err)
		}
	}
	out := eventExportWriter{w: &exportFaultWriter{}, format: "csv", name: "audit"}
	if err := out.write(json.RawMessage(`{"data":"invalid"}`)); err == nil {
		t.Fatal("CSV ignored invalid data")
	}
	if _, err := eventCSVRecord(json.RawMessage(`invalid`)); err == nil {
		t.Fatal("CSV ignored invalid envelope")
	}
}

func TestEventExportTransportAbort(t *testing.T) {
	e, h, cookie := exportServer(t)
	insertExportRow(t, e, "a", []map[string]any{{"type": "tg.sentry.audit.v1", "id": "first", "data": map[string]any{}}})
	insertExportRow(t, e, "z", "corrupt-events")
	server := httptest.NewServer(h)
	defer server.Close()
	for _, format := range []string{"json", "jsonl", "csv"} {
		req, err := http.NewRequest("GET", server.URL+"/api/v1/audit/export?format="+format, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(cookie)
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 200 || err == nil || !strings.Contains(string(body), "first") || strings.Contains(string(body), "error") {
			t.Fatal(format, response.StatusCode, string(body), err)
		}
	}
}
