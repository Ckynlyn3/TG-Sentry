package bridge

import (
	"aegishook/internal/core"
	"encoding/json"
	"maps"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The four outcomes are the named local #69 contract, not a vendor API or
// proof that the future server operation implements these fixture semantics.
func TestToolOutputOperationContract(t *testing.T) {
	request := []byte(`{"operation":"transform_tool_output","text":"fixture@example.invalid"}`)
	var input map[string]string
	if err := json.Unmarshal(request, &input); err != nil || len(input) != 2 || input["operation"] != "transform_tool_output" {
		t.Fatal("invalid original-leaf operation request", err)
	}
	rewritten, err := core.RedactSensitive(input["text"], []core.SensitiveFinding{{EntityType: "EMAIL_ADDRESS", Span: &core.SensitiveSpan{StartUTF16: 0, EndUTF16: len(input["text"])}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		outcome, response, wantText string
		withText                    bool
	}{
		{"unchanged", `{"outcome":"unchanged"}`, "", false},
		{"rewritten", `{"outcome":"rewritten","text":"[EMAIL_ADDRESS]"}`, rewritten, true},
		{"withheld", `{"outcome":"withheld","text":"[REDACTED]"}`, "[REDACTED]", true},
		{"unavailable", `{"outcome":"unavailable"}`, "", false},
	} {
		t.Run(tc.outcome, func(t *testing.T) {
			var response map[string]string
			if err := json.Unmarshal([]byte(tc.response), &response); err != nil {
				t.Fatal(err)
			}
			text, present := response["text"]
			wantFields := 1
			if tc.withText {
				wantFields++
			}
			if len(response) != wantFields || response["outcome"] != tc.outcome || present != tc.withText || text != tc.wantText {
				t.Fatal("operation response violates the documented outcome/text shape")
			}
		})
	}
}

// Static contract examples, not host-runtime acceptance or adapter wiring tests.
// The authoritative boundary is docs/research/AGENT-HOOK-CONTRACTS.md, issue #69.
func TestToolOutputRewriteContract(t *testing.T) {
	for _, tc := range []struct {
		name, client, version, event, field, result string
		leaves                                      []string
		dropStructured                              bool
	}{
		{"claude-mcp", "claude", "UNVERIFIED", "PostToolUse", "hookSpecificOutput.updatedToolOutput", "tool_response", []string{"tool_response.content.0.text"}, false},
		{"cursor-mcp", "cursor", "UNVERIFIED", "postToolUse", "updated_mcp_tool_output", "tool_output", []string{"tool_output.content.0.text", "tool_output.content.1.resource.text"}, false},
		{"opencode-native", "opencode", "v1.3.0", "tool.execute.after", "output", "output", []string{"output.output"}, false},
		{"opencode-mcp", "opencode", "v1.3.0", "tool.execute.after", "output", "output", []string{"output.content.0.text", "output.content.1.resource.text"}, false},
		{"pi", "pi", "1.3.0", "tool_result", "content", "content", []string{"content.0.text"}, true},
		{"openclaw", "openclaw", "2026.10.4", "tool_result_persist", "message", "message", []string{"message.content.0.text"}, false},
		{"codex-negative", "codex", "UNVERIFIED", "PostToolUse", "", "", nil, false},
		{"cursor-non-mcp-negative", "cursor", "UNVERIFIED", "postToolUse", "", "", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile("testdata/output-rewrite/" + tc.name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var f struct {
				Client, Version, Event       string
				Input, Response, Replacement map[string]any
			}
			if err := json.Unmarshal(data, &f); err != nil {
				t.Fatal(err)
			}
			if f.Client != tc.client || f.Version != tc.version || f.Event != tc.event {
				t.Fatal("fixture identity differs from the native contract")
			}
			if f.Input == nil || f.Response == nil || f.Replacement == nil {
				t.Fatal("missing native input, response or applied replacement")
			}
			if tc.field == "" {
				if len(f.Response) != 0 || !reflect.DeepEqual(f.Input, f.Replacement) {
					t.Fatal("detection-only client emitted fields or changed its result")
				}
				return
			}
			if tc.client == "cursor" {
				tool, _ := f.Input["tool_name"].(string)
				if !strings.HasPrefix(tool, "MCP:") {
					t.Fatal("Cursor rewrite requires a verified MCP event")
				}
				encoded, ok := f.Input["tool_output"].(string)
				var parsed map[string]any
				if !ok || json.Unmarshal([]byte(encoded), &parsed) != nil || parsed == nil {
					t.Fatal("Cursor tool_output must be a JSON-stringified object")
				}
				f.Input = maps.Clone(f.Input)
				f.Input["tool_output"] = parsed
			}
			assertNativeRewriteResponse(t, tc.client, tc.field, tc.result, f.Response, f.Replacement)
			assertRewriteLeaves(t, "", f.Input, f.Replacement, tc.leaves, tc.dropStructured)
			if reflect.DeepEqual(f.Input, f.Replacement) {
				t.Fatal("rewrite fixture did not exercise replacement")
			}
		})
	}
}

func assertNativeRewriteResponse(t *testing.T, client, field, result string, response, replacement map[string]any) {
	t.Helper()
	native := response
	if client == "claude" {
		var ok bool
		native, ok = response["hookSpecificOutput"].(map[string]any)
		if !ok || len(response) != 1 || len(native) != 2 || native["hookEventName"] != "PostToolUse" {
			t.Fatal("Claude requires only the PostToolUse hookSpecificOutput envelope")
		}
		field = "updatedToolOutput"
	} else if len(response) != 1 {
		t.Fatal("response contains missing or forbidden native fields")
	}
	value, present := native[field]
	if !present || value == nil || !reflect.DeepEqual(value, replacement[result]) {
		t.Fatal("required native replacement field missing or differs from applied result")
	}
	if client == "cursor" {
		if _, ok := value.(map[string]any); !ok {
			t.Fatal("Cursor updated_mcp_tool_output must be an object")
		}
	}
}

// Only explicitly supported original text leaves may differ. Comparing all other
// fields also guards call/session IDs, roles, status, attachments and metadata.
func assertRewriteLeaves(t *testing.T, path string, before, after any, leaves []string, dropStructured bool) {
	t.Helper()
	for _, leaf := range leaves {
		if path == leaf {
			original, ok := before.(string)
			if !ok {
				t.Fatal("original rewrite leaf is not text", path)
			}
			// Span covers this synthetic original leaf, never the serialized envelope.
			want, err := core.RedactSensitive(original, []core.SensitiveFinding{{EntityType: "EMAIL_ADDRESS", Span: &core.SensitiveSpan{StartUTF16: 0, EndUTF16: len(original)}}})
			if err != nil || after != want || original == want {
				t.Fatal("fixture does not match the original-leaf RedactSensitive output", path, err)
			}
			return
		}
	}
	switch original := before.(type) {
	case map[string]any:
		replaced, ok := after.(map[string]any)
		if !ok {
			t.Fatal("object shape changed", path)
		}
		wantKeys := len(original)
		if dropStructured && path == "" {
			if _, exists := original["structuredContent"]; exists {
				wantKeys--
			}
		}
		if len(replaced) != wantKeys {
			t.Fatal("structural fields added or removed", path)
		}
		for key, value := range original {
			if dropStructured && path == "" && key == "structuredContent" {
				if _, exists := replaced[key]; exists {
					t.Fatal("Pi content-only replacement must drop structuredContent")
				}
				continue
			}
			other, exists := replaced[key]
			if !exists {
				t.Fatal("structural field removed", path, key)
			}
			next := key
			if path != "" {
				next = path + "." + key
			}
			assertRewriteLeaves(t, next, value, other, leaves, dropStructured)
		}
	case []any:
		replaced, ok := after.([]any)
		if !ok || len(original) != len(replaced) {
			t.Fatal("content/attachment array shape changed", path)
		}
		for i, value := range original {
			assertRewriteLeaves(t, path+"."+strconv.Itoa(i), value, replaced[i], leaves, dropStructured)
		}
	default:
		if !reflect.DeepEqual(before, after) {
			t.Fatal("excluded surface or structural ID/status changed", path)
		}
	}
}
