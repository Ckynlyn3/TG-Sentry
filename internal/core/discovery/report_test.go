package discovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const validReportJSON = `{"schemaVersion":"discovery/v1","nodeId":"node","scope":"own_home","mode":"full","final":true,"scanStartedAt":"2026-10-19T10:00:00Z","scanCompletedAt":"2026-10-19T10:01:00Z","accounts":[{"observedLocalAccount":"fixture","accountId":"501","homePath":"/fixture","homeState":"readable","agents":[{"family":"claude","found":"found","evidence":{"kind":"config_file","relPath":".claude.json","mtime":"2026-10-19T09:00:00Z"},"version":"unknown","categories":[{"category":"memory","scope":"home","scanState":"scanned","assets":[{"assetId":"fixture-asset","name":"CLAUDE.md","category":"memory","sourceRelPath":".claude/CLAUDE.md","size":0,"mtime":"2026-10-19T09:00:00Z","hash":"fixture-hash","hashKind":"file_sha256"}]},{"category":"memory","scope":"project","scanState":"not_scanned","reason":"project_scope_deferred","assets":[]},{"category":"memory","scope":"auto_memory","scanState":"not_scanned","reason":"project_scope_deferred","assets":[]}]}]}]}`

func TestReportRoundTripAndScopedCategoryState(t *testing.T) {
	r, err := DecodeReport(strings.NewReader(validReportJSON + "\n\t "))
	if err != nil {
		t.Fatal(err)
	}
	categories := r.Accounts[0].Agents[0].Categories
	if len(categories[0].Assets) != 1 || categories[1].Reason != ReasonProjectScopeDeferred || categories[2].Scope != ScopeAutoMemory {
		t.Fatal("home assets were lost while project and auto-memory scopes were deferred")
	}
	if categories[0].Assets[0].Size == nil || *categories[0].Assets[0].Size != 0 {
		t.Fatal("known zero-byte file size must differ from omitted size")
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	again, err := DecodeReport(strings.NewReader(string(b)))
	if err != nil || !reflect.DeepEqual(again, r) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestDecodeReportRejectsUnknownFieldsAndTrailingData(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"unknown top-level", strings.Replace(validReportJSON, `"nodeId":"node"`, `"nodeId":"node","SENTINEL_unknown":"SENTINEL_secret"`, 1)},
		{"content asset", strings.Replace(validReportJSON, `"assetId":"fixture-asset"`, `"assetId":"fixture-asset","content":"SENTINEL_secret"`, 1)},
		{"content evidence", strings.Replace(validReportJSON, `"kind":"config_file"`, `"kind":"config_file","content":"SENTINEL_secret"`, 1)},
		{"second object", validReportJSON + `{}`},
		{"trailing junk", validReportJSON + `SENTINEL_secret`},
		{"empty", ""}, {"null", "null"}, {"array", "[]"},
		{"malformed", `{"SENTINEL_secret`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeReport(strings.NewReader(tc.input))
			if err == nil {
				t.Fatal("invalid report accepted")
			}
			if strings.Contains(err.Error(), "SENTINEL") {
				t.Fatalf("source data leaked through error: %v", err)
			}
		})
	}
}

func TestReportRejectsInvalidContractEnums(t *testing.T) {
	for _, pair := range [][2]string{
		{`"discovery/v1"`, `"discovery/v2"`},
		{`"own_home"`, `"other"`}, {`"full"`, `"partial"`},
		{`"final":true`, `"final":false`},
		{`"readable"`, `"other"`}, {`"found":"found"`, `"found":"other"`},
		{`"version":"unknown"`, `"version":"executed"`},
		{`"scope":"home"`, `"scope":"other"`},
		{`"scanned"`, `"stale"`},
		{`"project_scope_deferred"`, `"SENTINEL_reason"`},
		{`"file_sha256"`, `"other"`},
	} {
		t.Run(pair[1], func(t *testing.T) {
			_, err := DecodeReport(strings.NewReader(strings.Replace(validReportJSON, pair[0], pair[1], 1)))
			if err == nil || strings.Contains(err.Error(), "SENTINEL") {
				t.Fatalf("expected sanitized validation failure, got %v", err)
			}
		})
	}
}

func TestReportAcceptsClosedReasonsAndStates(t *testing.T) {
	for _, reason := range []Reason{ReasonProjectScopeDeferred, ReasonUnreadable, ReasonNotRegularFile, ReasonEscapedRoot, ReasonParseFailed, ReasonTooLarge, ReasonTooManyEntries, ReasonChangedDuringRead, ReasonCanceled, ReasonUnparsedFormat, ReasonTGTargetOnly, ReasonHomeDenied, ReasonHomeUnavailable, ReasonOwnerMismatch} {
		input := strings.ReplaceAll(validReportJSON, "project_scope_deferred", string(reason))
		if _, err := DecodeReport(strings.NewReader(input)); err != nil {
			t.Fatalf("reason %s: %v", reason, err)
		}
	}
	for _, state := range []ScanState{ScanNotSupported, ScanNotScanned, ScanScanned, ScanError, ScanUnknown} {
		if _, err := DecodeReport(strings.NewReader(strings.Replace(validReportJSON, `"scanned"`, `"`+string(state)+`"`, 1))); err != nil {
			t.Fatalf("state %s: %v", state, err)
		}
	}
	for _, found := range []FoundState{Found, NotFound, FoundUnknown} {
		if _, err := DecodeReport(strings.NewReader(strings.Replace(validReportJSON, `"found":"found"`, `"found":"`+string(found)+`"`, 1))); err != nil {
			t.Fatalf("found %s: %v", found, err)
		}
	}
	for _, state := range []HomeState{HomeDenied, HomeUnavailable} {
		if _, err := DecodeReport(strings.NewReader(strings.Replace(validReportJSON, `"readable"`, `"`+string(state)+`"`, 1))); err != nil {
			t.Fatalf("home state %s: %v", state, err)
		}
	}
	if _, err := DecodeReport(strings.NewReader(strings.Replace(validReportJSON, `"own_home"`, `"all_local_accounts"`, 1))); err != nil {
		t.Fatal(err)
	}
}

func TestReportRejectsDuplicateAssetAcrossScopesAndAccounts(t *testing.T) {
	r, err := DecodeReport(strings.NewReader(validReportJSON))
	if err != nil {
		t.Fatal(err)
	}
	r.Accounts = append(r.Accounts, r.Accounts[0])
	if err := r.Validate(); !errors.Is(err, ErrDuplicateAsset) {
		t.Fatalf("expected duplicate_asset, got %v", err)
	}
}

func TestMCPDescriptorHasOnlyProjectionFields(t *testing.T) {
	input := strings.Replace(validReportJSON, `"hashKind":"file_sha256"`, `"hashKind":"descriptor_sha256","descriptor":{"name":"fixture","transport":"stdio","envKeys":["TOKEN"],"headerKeys":["Authorization"]}`, 1)
	if _, err := DecodeReport(strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"command", "args", "url", "env", "headers", "content"} {
		bad := strings.Replace(input, `"transport":"stdio"`, `"transport":"stdio","`+field+`":"SENTINEL_secret"`, 1)
		if _, err := DecodeReport(strings.NewReader(bad)); err == nil || strings.Contains(err.Error(), "SENTINEL") {
			t.Fatalf("descriptor %s must be rejected without exposing source, got %v", field, err)
		}
	}
}

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestDecodeReportReaderError(t *testing.T) {
	if _, err := DecodeReport(failedReader{}); !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("reader cause and sanitized contract error must be retained: %v", err)
	}
}

func TestDecodeReportRetainsHTTPBodyLimitError(t *testing.T) {
	// Use the real stdlib body-limit reader; S9 must distinguish 413 from 400.
	for _, limit := range []int64{1, int64(len(validReportJSON))} {
		r := http.MaxBytesReader(nil, io.NopCloser(strings.NewReader(validReportJSON+" ")), limit)
		_, err := DecodeReport(r)
		var tooLarge *http.MaxBytesError
		if !errors.As(err, &tooLarge) || tooLarge.Limit != limit {
			t.Fatalf("body limit %d cause lost: %v", limit, err)
		}
	}
}

// Regression probes ported from the independent frozen-candidate review.
// Standards: RFC 8259 §§4,8; RFC 8785 §§3.1,3.2.2.2; Go encoding/json docs.
func reviewReport(t *testing.T) Report {
	t.Helper()
	r, err := DecodeReport(strings.NewReader(validReportJSON))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func reviewDecode(t *testing.T, r Report) error {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeReport(bytes.NewReader(b))
	return err
}
func TestReviewRejectDuplicateMembers(t *testing.T) {
	for _, tc := range []struct{ name, from, to string }{
		{"unknown_overwritten_by_not_found", `"found":"found"`, `"found":"unknown","found":"not_found"`},
		{"escaped_duplicate", `"found":"found"`, `"found":"unknown","\u0066ound":"not_found"`},
		{"case_alias_duplicate", `"found":"found"`, `"found":"unknown","Found":"not_found"`},
		{"category_state_duplicate", `"scanState":"scanned"`, `"scanState":"unknown","scanState":"scanned"`},
		{"schema_duplicate", `"schemaVersion":"discovery/v1"`, `"schemaVersion":"discovery/v2","schemaVersion":"discovery/v1"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := DecodeReport(strings.NewReader(strings.Replace(validReportJSON, tc.from, tc.to, 1)))
			if err == nil {
				t.Fatalf("ambiguous members accepted: found=%s homeScanState=%s", r.Accounts[0].Agents[0].Found, r.Accounts[0].Agents[0].Categories[0].ScanState)
			}
		})
	}
}
func TestReviewRejectInvalidSourcePaths(t *testing.T) {
	for _, p := range []string{"", "..", "../secret", ".claude/../../secret", "/etc/passwd", `C:\Users\other\secret`, `\\host\share\secret`, `.claude\CLAUDE.md`, ".claude/\x00CLAUDE.md"} {
		t.Run(fmt.Sprintf("%q", p), func(t *testing.T) {
			r := reviewReport(t)
			r.Accounts[0].Agents[0].Categories[0].Assets[0].SourceRelPath = p
			if err := r.Validate(); err == nil {
				t.Error("Validate accepted non-home-relative/non-normalized path")
			}
			if err := reviewDecode(t, r); err == nil {
				t.Error("DecodeReport accepted non-home-relative/non-normalized path")
			}
		})
	}
}
func TestReviewRejectInvalidUnicode(t *testing.T) {
	for _, s := range []string{".claude/\xff.md", ".claude/\xfe.md", `.claude/\ud800.md`} {
		t.Run(fmt.Sprintf("%q", s), func(t *testing.T) {
			raw := strings.Replace(validReportJSON, ".claude/CLAUDE.md", s, 1)
			r, err := DecodeReport(strings.NewReader(raw))
			if err == nil {
				t.Errorf("malformed Unicode accepted and changed to %q", r.Accounts[0].Agents[0].Categories[0].Assets[0].SourceRelPath)
			}
		})
	}
	r := reviewReport(t)
	r.Accounts[0].Agents[0].Categories[0].Assets[0].SourceRelPath = ".claude/\xff.md"
	if err := r.Validate(); err == nil {
		t.Error("Validate accepts invalid UTF-8 identity input")
	}
}
func TestReviewRejectInvalidCategories(t *testing.T) {
	for _, category := range []string{"", "SENTINEL_unsupported", "Skills"} {
		t.Run("enclosing_"+category, func(t *testing.T) {
			r := reviewReport(t)
			r.Accounts[0].Agents[0].Categories[0].Category = category
			if err := reviewDecode(t, r); err == nil {
				t.Error("invalid category accepted")
			}
		})
		t.Run("asset_"+category, func(t *testing.T) {
			r := reviewReport(t)
			r.Accounts[0].Agents[0].Categories[0].Assets[0].Category = category
			if err := reviewDecode(t, r); err == nil {
				t.Error("invalid asset category accepted")
			}
		})
	}
}
func TestReviewRejectDuplicateCategoryScope(t *testing.T) {
	r := reviewReport(t)
	agent := &r.Accounts[0].Agents[0]
	agent.Categories = append(agent.Categories, Category{Category: "memory", Scope: ScopeHome, ScanState: ScanUnknown})
	if err := reviewDecode(t, r); err == nil {
		t.Fatal("both scanned and unknown accepted for same (memory, home) key")
	}
}

// The accepted fix rejects malformed tuples instead of hashing lossy strings.
func TestReviewIDDistinctMalformedTuples(t *testing.T) {
	base := [6]string{"n", "501", "claude", "memory", ".claude/CLAUDE.md", "file"}
	for i := range base {
		for _, bad := range []string{"\xff", "\xfe"} {
			parts := base
			parts[i] = bad
			id, err := AssetID(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5])
			if id != "" || !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("malformed asset tuple accepted: %q, %v", id, err)
			}
		}
	}
}

func TestReviewAgentIDDistinctMalformedTuples(t *testing.T) {
	base := [3]string{"n", "501", "claude"}
	for i := range base {
		for _, bad := range []string{"\xff", "\xfe"} {
			parts := base
			parts[i] = bad
			id, err := DiscoveredAgentID(parts[0], parts[1], parts[2])
			if id != "" || !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("malformed agent tuple accepted: %q, %v", id, err)
			}
		}
	}
}

func TestReviewControls(t *testing.T) {
	t.Run("unknown_remains_unknown", func(t *testing.T) {
		r := reviewReport(t)
		a := &r.Accounts[0].Agents[0]
		a.Found = FoundUnknown
		a.Categories[0].ScanState = ScanUnknown
		a.Categories[0].Assets[0].Size = nil
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeReport(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		got := again.Accounts[0].Agents[0]
		if got.Found != FoundUnknown || got.Categories[0].ScanState != ScanUnknown || got.Categories[0].Assets[0].Size != nil {
			t.Fatal("unknown value collapsed")
		}
	})
	t.Run("unknown_fields_every_level_and_static_errors", func(t *testing.T) {
		for _, anchor := range []string{`"nodeId":"node"`, `"accountId":"501"`, `"family":"claude"`, `"kind":"config_file"`, `"scanState":"scanned"`, `"assetId":"fixture-asset"`} {
			raw := strings.Replace(validReportJSON, anchor, anchor+`,"SENTINEL_FIELD":"SENTINEL_VALUE"`, 1)
			_, err := DecodeReport(strings.NewReader(raw))
			if err == nil || err.Error() != "invalid discovery report" {
				t.Fatalf("unknown field not rejected with static error: %v", err)
			}
		}
	})
	t.Run("body_limit_exact_and_plus_one", func(t *testing.T) {
		const bodyLimit = 2 << 20 // approved plan §3.8; transport budget, not directory cap
		exact := validReportJSON + strings.Repeat(" ", bodyLimit-len(validReportJSON))
		for _, tc := range []struct {
			body     string
			overflow bool
		}{{exact, false}, {exact + " ", true}} {
			reader := http.MaxBytesReader(nil, io.NopCloser(strings.NewReader(tc.body)), bodyLimit)
			_, err := DecodeReport(reader)
			var maxErr *http.MaxBytesError
			if tc.overflow {
				if !errors.As(err, &maxErr) || maxErr.Limit != bodyLimit || err.Error() != "invalid discovery report" {
					t.Fatalf("lost or exposed limit cause %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("valid_unicode_tuple_boundaries", func(t *testing.T) {
		seen := map[string]string{}
		for _, s := range []string{"", "a", "a|b", "a,b", `a\"b`, "a\x00b", "é", "e\u0301", "𐀀", "<>&", "\u2028\u2029"} {
			for _, v := range [][3]string{{s, "x", "y"}, {"x", s, "y"}, {"x", "y", s}} {
				key := fmt.Sprintf("%q", v)
				id := testAgentID(t, v[0], v[1], v[2])
				if prior, ok := seen[id]; ok && prior != key {
					t.Fatalf("collision %s vs %s", prior, key)
				}
				seen[id] = key
				if again := testAgentID(t, v[0], v[1], v[2]); again != id {
					t.Fatal("unstable tuple encoding")
				}
			}
		}
	})
	t.Run("Go_encoding_not_JCS", func(t *testing.T) {
		// Plan explicitly specifies Go string-array encoding, not RFC 8785 JCS.
		encoded := `["\u003c\u003e\u0026","501","\u2028\u2029"]`
		digest := sha256.Sum256([]byte(encoded))
		expected := hex.EncodeToString(digest[:])
		if got := testAgentID(t, "<>&", "501", "\u2028\u2029"); got != expected {
			t.Fatalf("Go canonical vector differs: %s != %s", got, expected)
		}
		jcs := sha256.Sum256([]byte("[\"<>&\",\"501\",\"\u2028\u2029\"]"))
		if digest == jcs {
			t.Fatal("control must distinguish Go byte contract from JCS")
		}
	})
	t.Run("array_order_roundtrip", func(t *testing.T) {
		r := reviewReport(t)
		b, _ := json.Marshal(r)
		r2, err := DecodeReport(bytes.NewReader(b))
		if err != nil || !reflect.DeepEqual(r, r2) {
			t.Fatal("array ordering changed")
		}
	})
	t.Run("overcount_is_directory_not_report_limit", func(t *testing.T) {
		r := reviewReport(t)
		c := &r.Accounts[0].Agents[0].Categories[0]
		sample := c.Assets[0]
		c.Assets = nil
		for i := 0; i < 1025; i++ {
			a := sample
			a.AssetID = fmt.Sprintf("fixture-%d", i)
			c.Assets = append(c.Assets, a)
		}
		if err := reviewDecode(t, r); err != nil {
			t.Fatalf("directory budget incorrectly enforced as report asset cap: %v", err)
		}
	})
	t.Run("unbounded_reader_is_caller_responsibility", func(t *testing.T) {
		input := validReportJSON + strings.Repeat(" ", 2<<20)
		_, err := DecodeReport(strings.NewReader(input))
		t.Logf("unbounded oversized input accepted=%t; transport caller must use MaxBytesReader", err == nil)
	})
}

func TestReportUnicodeAtEveryStringBoundary(t *testing.T) {
	// Enumerate every string field, including optional descriptor key arrays.
	r := reviewReport(t)
	r.Accounts[0].Agents[0].Categories[0].Assets[0].Descriptor = &MCPDescriptor{
		Name: "mcp", Transport: "stdio", EnvKeys: []string{"KEY"}, HeaderKeys: []string{"Header"},
	}
	var visit func(reflect.Value, []int)
	visit = func(v reflect.Value, path []int) {
		switch v.Kind() {
		case reflect.Struct:
			if v.Type().PkgPath() == "time" {
				return
			}
			for i := 0; i < v.NumField(); i++ {
				visit(v.Field(i), append(append([]int(nil), path...), i))
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				visit(v.Index(i), append(append([]int(nil), path...), i))
			}
		case reflect.Pointer:
			if !v.IsNil() {
				visit(v.Elem(), path)
			}
		case reflect.String:
			t.Run(fmt.Sprint(path), func(t *testing.T) {
				original := v.String()
				defer v.SetString(original)
				v.SetString("\xff")
				if err := r.Validate(); err != ErrInvalidReport {
					t.Fatalf("invalid direct string accepted: %v", err)
				}
				v.SetString("SENTINEL_UNICODE")
				b, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				for _, bad := range []string{"\xff", `\ud800`, `\udc00`, `\ud800x`, `\ud800\u0041`} {
					input := strings.Replace(string(b), "SENTINEL_UNICODE", bad, 1)
					if _, err := DecodeReport(strings.NewReader(input)); err == nil || err.Error() != ErrInvalidReport.Error() {
						t.Fatalf("invalid wire string accepted or leaked: %v", err)
					}
				}
			})
		}
	}
	visit(reflect.ValueOf(&r).Elem(), nil)
}

func TestReportValidUnicodeAndWirePaths(t *testing.T) {
	for _, path := range []string{"a", ".claude/日本語.md", "folder/𐀀.md", "a/�.md", "abc:def/file"} {
		r := reviewReport(t)
		r.Accounts[0].Agents[0].Categories[0].Assets[0].SourceRelPath = path
		if err := reviewDecode(t, r); err != nil {
			t.Fatalf("valid path %q: %v", path, err)
		}
	}
	for _, escaped := range []string{`\ud800\udc00`, `\uD83D\uDE00`, `\ufffd`, `\\ud800`} {
		input := strings.Replace(validReportJSON, `"nodeId":"node"`, `"nodeId":"`+escaped+`"`, 1)
		if _, err := DecodeReport(strings.NewReader(input)); err != nil {
			t.Fatalf("valid Unicode escape %s: %v", escaped, err)
		}
	}
	for _, path := range []string{".", "a//b", "a/./b", "a/../b", "a/", "C:relative", "z:/absolute"} {
		r := reviewReport(t)
		r.Accounts[0].Agents[0].Categories[0].Assets[0].SourceRelPath = path
		if err := r.Validate(); err != ErrInvalidReport {
			t.Fatalf("invalid path %q accepted", path)
		}
	}
	for _, category := range []string{"skills", "mcp", "plugins", "builtin_tools", "memory"} {
		r := reviewReport(t)
		r.Accounts[0].Agents[0].Categories[0].Category = category
		r.Accounts[0].Agents[0].Categories[0].Assets[0].Category = category
		if err := reviewDecode(t, r); err != nil {
			t.Fatalf("valid category %q: %v", category, err)
		}
	}
}

func TestReportDuplicateMemberBoundaries(t *testing.T) {
	for _, input := range []string{
		`{"nodeId":"a","nodeID":"b"}`,
		`{"S":"a","ſ":"b"}`,
		`{"K":"a","K":"b"}`,
		`{"a":{"x":1,"X":2}}`,
		`{"a":[{"x":1,"\u0078":2}]}`,
		`{"nodeId":"a","\ud800":"x"}`,
		`{"nodeId":`, `{"nodeId"`, `{"nodeId":[]`, `{"nodeId":{`,
		`{"nodeId":{"a":}}`, `{"nodeId":[}`, `{"nodeId":1e999}`, `{"nodeId":"a",true:1}`,
	} {
		if _, err := DecodeReport(strings.NewReader(input)); err == nil || err.Error() != ErrInvalidReport.Error() {
			t.Fatalf("ambiguous or malformed JSON accepted: %v", err)
		}
	}
}

func TestProvisionalResourceBudgets(t *testing.T) {
	if ConfigParseBudgetBytes != 2<<20 || DirectoryEntryBudget != 1024 {
		t.Fatal("binding R7 budgets changed")
	}
}
