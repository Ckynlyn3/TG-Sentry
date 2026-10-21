package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type contextSourceFixture struct {
	Name         string               `json:"name"`
	Input        map[string]any       `json:"input"`
	Observations []ContextObservation `json:"observations"`
}

func contextFixture[T any](t *testing.T, name string) T {
	t.Helper()
	data, err := os.ReadFile("testdata/context-observations/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func contextMeta(t *testing.T, kind ContextObservationKind) ContextObservationMeta {
	t.Helper()
	hook := "llm_input.systemPrompt"
	if kind == ContextObservationToolDefinitions {
		hook = "llm_input.tools"
	}
	return ContextObservationMeta{
		ID: "synthetic-observation", Kind: kind, Coverage: ContextCoverageObserved,
		Source:    ContextObservationSource{Adapter: "openclaw", AdapterVersion: "2026.10.4", Hook: hook, SourceRevision: "383c124cc32ffee3f8e56f549b88da94d269a4af"},
		SessionID: "synthetic-session", InstanceID: "synthetic-instance", ObservedAt: time.Date(2026, 10, 21, 1, 2, 3, 0, time.UTC),
	}
}

func contextCapture(t *testing.T, meta ContextObservationMeta, payload []byte) ContextObservation {
	t.Helper()
	out, err := CaptureContextObservation(meta, payload)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestContextObservationSourceFixtures(t *testing.T) {
	for _, source := range []string{"openclaw", "pi"} {
		for _, fixture := range contextFixture[[]contextSourceFixture](t, source) {
			t.Run(source+"/"+fixture.Name, func(t *testing.T) {
				for _, want := range fixture.Observations {
					var payload any
					if want.Kind == ContextObservationInstructions {
						if prompt, ok := fixture.Input["systemPrompt"]; ok {
							payload = []any{map[string]any{"type": "text", "content": prompt}}
						}
					} else if source == "openclaw" {
						payload = fixture.Input["tools"]
					} else {
						active := map[string]bool{}
						for _, name := range fixture.Input["activeTools"].([]any) {
							active[name.(string)] = true
						}
						tools := []any{}
						for _, value := range fixture.Input["allTools"].([]any) {
							tool := value.(map[string]any)
							if active[tool["name"].(string)] {
								tools = append(tools, map[string]any{"type": "function", "name": tool["name"], "description": tool["description"], "parameters": tool["parameters"]})
							}
						}
						payload = tools
					}
					var data []byte
					if payload != nil {
						var err error
						data, err = json.Marshal(payload)
						if err != nil {
							t.Fatal(err)
						}
					}
					got := contextCapture(t, want.ContextObservationMeta, data)
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("surface contract mismatch: got %+v, want %+v", got, want)
					}
					wire, err := json.Marshal(got)
					if err != nil {
						t.Fatal(err)
					}
					for _, excluded := range []string{"excluded-user-message", "excluded-history", "excluded-inactive-tool", "synthetic-run-not-an-attempt-id", "nativeAttemptId"} {
						if bytes.Contains(wire, []byte(excluded)) {
							t.Fatalf("non-surface material retained: %s", excluded)
						}
					}
					if source == "pi" && got.Coverage != "prepared" || source == "openclaw" && got.Coverage != "observed" {
						t.Fatal("upgraded adapter coverage")
					}
				}
			})
		}
	}
}

func TestContextObservationUnsupportedSources(t *testing.T) {
	for _, want := range contextFixture[[]ContextObservation](t, "unavailable") {
		got := contextCapture(t, want.ContextObservationMeta, nil)
		if !reflect.DeepEqual(got, want) || got.ContentState != "never_captured" || got.Source.Hook != "" {
			t.Fatalf("unsupported source claims capture: %+v", got)
		}
		if _, err := CaptureContextObservation(want.ContextObservationMeta, []byte(`[]`)); err == nil {
			t.Fatalf("unsupported adapter accepted content: %s", want.Source.Adapter)
		}
	}
}

func TestContextObservationWireStates(t *testing.T) {
	captured := contextCapture(t, contextMeta(t, ContextObservationInstructions), []byte(`[{"type":"text","content":"Read-only workspace instructions."}]`))
	for _, state := range []ContentState{ContentCaptured, ContentPolicyOmitted, ContentNotYetAvailable, ContentPermissionRestricted, ContentNeverCaptured} {
		t.Run(string(state), func(t *testing.T) {
			want := captured
			want.ContentState = state
			if state != ContentCaptured {
				want.Instructions, want.EpochDigest = nil, ""
			}
			data, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			var got ContextObservation
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) || got.ContentState != state {
				t.Fatalf("state round-trip: got %+v, want %+v", got, want)
			}
		})
	}
}

func TestContextObservationRejectsInvalidWire(t *testing.T) {
	captured := contextCapture(t, contextMeta(t, ContextObservationInstructions), []byte(`[{"type":"text","content":"safe"}]`))
	data, err := json.Marshal(captured)
	if err != nil {
		t.Fatal(err)
	}
	patches := map[string]func(map[string]any){
		"missing digest":   func(v map[string]any) { delete(v, "epochDigest") },
		"uppercase digest": func(v map[string]any) { v["epochDigest"] = strings.Repeat("A", 64) },
		"missing payload":  func(v map[string]any) { delete(v, "instructions") },
		"both payloads": func(v map[string]any) {
			v["toolDefinitions"] = map[string]any{"attribute": "gen_ai.tool.definitions", "items": []any{}}
		},
		"both payload keys with null tools": func(v map[string]any) { v["toolDefinitions"] = nil },
		"both payload keys with null instructions": func(v map[string]any) {
			v["kind"], v["instructions"] = "tool_definitions", nil
			v["source"].(map[string]any)["hook"] = "llm_input.tools"
			v["toolDefinitions"] = map[string]any{"attribute": "gen_ai.tool.definitions", "items": []any{}}
		},
		"wrong kind":      func(v map[string]any) { v["kind"] = "tool_definitions" },
		"wrong attribute": func(v map[string]any) { v["instructions"].(map[string]any)["attribute"] = "gen_ai.input.messages" },
		"null array":      func(v map[string]any) { v["instructions"].(map[string]any)["parts"] = nil },
		"untyped part": func(v map[string]any) {
			v["instructions"].(map[string]any)["parts"] = []any{map[string]any{"content": "safe"}}
		},
		"unknown state":          func(v map[string]any) { v["contentState"] = "not_recorded" },
		"tenant assertion":       func(v map[string]any) { v["tenant"] = "default" },
		"unknown envelope field": func(v map[string]any) { v["prompt"] = "not an instruction surface" },
		"missing source field":   func(v map[string]any) { delete(v["source"].(map[string]any), "hook") },
		"null source field":      func(v map[string]any) { v["source"].(map[string]any)["adapterVersion"] = nil },
		"unknown source":         func(v map[string]any) { v["source"].(map[string]any)["adapter"] = "unknown" },
		"unadmitted version":     func(v map[string]any) { v["source"].(map[string]any)["adapterVersion"] = "other" },
		"unadmitted revision":    func(v map[string]any) { v["source"].(map[string]any)["sourceRevision"] = "other" },
		"upgraded coverage":      func(v map[string]any) { v["coverage"] = "submitted" },
		"missing time":           func(v map[string]any) { delete(v, "observedAt") },
		"invalid time":           func(v map[string]any) { v["observedAt"] = "2026-10-21T01:02:03+99:99" },
		"null association":       func(v map[string]any) { v["nativeAttemptId"] = nil },
	}
	for _, state := range []string{"policy_omitted", "not_yet_available", "permission_restricted", "never_captured"} {
		patches[state+" with content"] = func(v map[string]any) { v["contentState"] = state }
		patches[state+" with null payload"] = func(v map[string]any) { v["contentState"], v["instructions"] = state, nil }
		patches[state+" with empty tool set"] = func(v map[string]any) {
			v["contentState"], v["kind"] = state, "tool_definitions"
			delete(v, "instructions")
			v["toolDefinitions"] = map[string]any{"attribute": "gen_ai.tool.definitions", "items": []any{}}
		}
	}
	for name, patch := range patches {
		t.Run(name, func(t *testing.T) {
			var v map[string]any
			if err := json.Unmarshal(data, &v); err != nil {
				t.Fatal(err)
			}
			patch(v)
			wire, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			var out ContextObservation
			if err := json.Unmarshal(wire, &out); err == nil {
				t.Fatalf("accepted invalid observation: %s", wire)
			}
		})
	}
	bad := captured
	bad.ToolDefinitions = &ContextToolDefinitions{Attribute: "gen_ai.tool.definitions", Items: []map[string]any{}}
	if _, err := json.Marshal(bad); err == nil {
		t.Fatal("marshaled both payloads")
	}
}

type contextWireNegative struct {
	Name  string         `json:"name"`
	Rule  string         `json:"rule"`
	Value map[string]any `json:"value"`
}

// TestContextObservationSharedWireNegatives consumes the same fixture file as
// console/src/lib/contextObservation.schema.test.ts (Zod and the OpenAPI schema
// check), so the three validators cannot drift on the closed-object boundary.
func TestContextObservationSharedWireNegatives(t *testing.T) {
	for _, negative := range contextFixture[[]contextWireNegative](t, "wire-negatives") {
		t.Run(negative.Rule+"/"+negative.Name, func(t *testing.T) {
			wire, err := json.Marshal(negative.Value)
			if err != nil {
				t.Fatal(err)
			}
			var out ContextObservation
			if err := json.Unmarshal(wire, &out); err == nil {
				t.Fatalf("accepted shared negative %q: %s", negative.Name, wire)
			}
		})
	}
}

func TestContextObservationPayloadByteBound(t *testing.T) {
	// The bound is the existing 2 MiB JSON request-body ceiling
	// (internal/server/server.go:67, http.MaxBytesReader); no new number.
	const limit = ContextObservationByteLimit
	if limit != 2<<20 {
		t.Fatalf("bound drifted from the server request-body precedent: %d", limit)
	}
	// JSON permits insignificant whitespace, so the exact bound is reached
	// without a >24000-byte string, which RedactText would truncate.
	pad := func(size int) []byte {
		const body = `[{"type":"text","content":"safe"}]`
		return append([]byte(body), bytes.Repeat([]byte(" "), size-len(body))...)
	}
	at := pad(limit)
	if got := contextCapture(t, contextMeta(t, ContextObservationInstructions), at); got.ContentState != ContentCaptured {
		t.Fatalf("payload at the bound was not captured: %+v", got)
	}
	over := pad(limit + 1)
	if _, err := CaptureContextObservation(contextMeta(t, ContextObservationInstructions), over); err == nil {
		t.Fatalf("accepted a %d-byte payload over the %d bound", len(over), limit)
	}
	record := func(size int) []byte {
		value := contextCapture(t, contextMeta(t, ContextObservationInstructions), []byte(`[{"type":"text","content":""}]`))
		base, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		value.Instructions.Parts[0]["content"] = strings.Repeat("a", size-len(base))
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) != size {
			t.Fatalf("record is %d bytes, want %d", len(data), size)
		}
		return data
	}
	var out ContextObservation
	if err := json.Unmarshal(record(limit), &out); err != nil {
		t.Fatalf("record at the bound was rejected: %v", err)
	}
	if err := json.Unmarshal(record(limit+1), &out); err == nil {
		t.Fatal("accepted an over-bound record")
	}
}

func TestContextObservationPinnedAnyOfAndExtensions(t *testing.T) {
	for _, tc := range []struct {
		kind    ContextObservationKind
		payload string
	}{
		{ContextObservationInstructions, `[{"type":"text"},{"type":"text","content":null,"extension":{"labels":["safe"],"enabled":true}},{"type":"vendor","value":1}]`},
		{ContextObservationToolDefinitions, `[{"type":"function","name":"nullable","description":null,"parameters":null},{"type":"function","name":"boolean-schema","parameters":false},{"type":"function","name":"generic-overlap","description":7,"parameters":{"type":7}},{"type":"vendor","name":"custom","extension":{"labels":["safe"]}}]`},
	} {
		got := contextCapture(t, contextMeta(t, tc.kind), []byte(tc.payload))
		var want []map[string]any
		if err := json.Unmarshal([]byte(tc.payload), &want); err != nil {
			t.Fatal(err)
		}
		var payload []map[string]any
		if got.Instructions != nil {
			payload = got.Instructions.Parts
		} else {
			payload = got.ToolDefinitions.Items
		}
		if got.ContentState != "captured" || !reflect.DeepEqual(payload, want) {
			t.Fatalf("lost upstream anyOf branch/extension/null: %+v", got)
		}
	}
	if _, err := CaptureContextObservation(contextMeta(t, ContextObservationToolDefinitions), []byte(`[{"type":"function"}]`)); err == nil {
		t.Fatal("tool without a name passed both branches")
	}
}

func TestContextObservationRedactsEveryRetainedString(t *testing.T) {
	const canary = "Bearer synthetic-observation-canary"
	const pem = "-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElDLU9OTFk=\nU1lOVEhFVElDLU9OTFk=\nU1lOVEhFVElDLU9OTFk=\nU1lOVEhFVElDLU9OTFk=\n-----END PRIVATE KEY-----"
	for _, tc := range []struct {
		name    string
		kind    ContextObservationKind
		payload any
	}{
		{"instruction", ContextObservationInstructions, []any{map[string]any{"type": "text", "content": canary}}},
		{"generic part type", ContextObservationInstructions, []any{map[string]any{"type": canary}}},
		{"part extension", ContextObservationInstructions, []any{map[string]any{"type": "vendor", "extension": map[string]any{"nested": []any{canary}}}}},
		{"part extension key", ContextObservationInstructions, []any{map[string]any{"type": "vendor", canary: "safe"}}},
		{"tool name", ContextObservationToolDefinitions, []any{map[string]any{"type": "function", "name": canary}}},
		{"tool type", ContextObservationToolDefinitions, []any{map[string]any{"type": canary, "name": "safe"}}},
		{"description", ContextObservationToolDefinitions, []any{map[string]any{"type": "function", "name": "safe", "description": canary}}},
		{"nested parameter description", ContextObservationToolDefinitions, []any{map[string]any{"type": "function", "name": "safe", "parameters": map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"description": canary}}}}}},
		{"tool extension", ContextObservationToolDefinitions, []any{map[string]any{"type": "vendor", "name": "safe", "extension": []any{map[string]any{"value": canary}}}}},
		{"tool extension key", ContextObservationToolDefinitions, []any{map[string]any{"type": "function", "name": "safe", canary: false}}},
		{"multiline original PEM", ContextObservationInstructions, []any{map[string]any{"type": "text", "content": pem}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			before := bytes.Clone(data)
			got := contextCapture(t, contextMeta(t, tc.kind), data)
			wire, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if got.ContentState != "policy_omitted" || got.Instructions != nil || got.ToolDefinitions != nil || got.EpochDigest != "" || got.SensitiveInfo == nil || got.SensitiveInfo.Decision != "reject" || got.SensitiveInfo.Reason == "" {
				t.Fatalf("expected whole-content omission with sensitivity metadata: %s", wire)
			}
			for _, marker := range []string{canary, "U1lOVEhFVElDLU9OTFk=", "[REDACTED]", `"instructions":`, `"toolDefinitions":`, `"epochDigest"`} {
				if bytes.Contains(wire, []byte(marker)) {
					t.Fatalf("retained sensitive payload/digest/replacement: %s", marker)
				}
			}
			if !bytes.Equal(data, before) {
				t.Fatal("mutated caller's payload")
			}
		})
	}
	invalidUTF8 := []byte(`[{"type":"text","content":"`)
	invalidUTF8 = append(invalidUTF8, 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`"}]`)...)
	got := contextCapture(t, contextMeta(t, ContextObservationInstructions), invalidUTF8)
	if got.ContentState != "policy_omitted" || got.SensitiveInfo == nil || !got.SensitiveInfo.Unavailable || got.Instructions != nil {
		t.Fatalf("unavailable detector did not omit content: %+v", got)
	}
	clean := contextCapture(t, contextMeta(t, ContextObservationInstructions), []byte(`[{"type":"text","content":"safe"}]`))
	if clean.ContentState != "captured" || clean.Instructions.Parts[0]["content"] != "safe" || clean.SensitiveInfo != nil {
		t.Fatalf("clean observation was omitted: %+v", clean)
	}
}

func TestContextObservationDigestDecodedKeys(t *testing.T) {
	first := []byte(`[{"type":"function","name":"query","description":null,"parameters":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}},{"type":"custom","name":"catalog","extension":{"labels":["read-only"]}}]`)
	reordered := []byte(`[{"parameters":{"required":["query"],"properties":{"query":{"type":"string"}},"type":"object"},"description":null,"name":"query","type":"function"},{"extension":{"labels":["read-only"]},"type":"custom","name":"catalog"}]`)
	for _, data := range [][]byte{first, reordered} {
		got, err := ContextObservationDigest(data)
		if err != nil || got != "ad19f1e4cba481d02b3bd6b9d4a779a3f3ac1f86c28ee649c5613580b33bfb7b" {
			t.Fatalf("decoded digest = %q / %v", got, err)
		}
	}
	if _, err := ContextObservationDigest([]byte(`[{`)); err == nil {
		t.Fatal("invalid JSON had a digest")
	}
	empty := contextCapture(t, contextMeta(t, ContextObservationToolDefinitions), []byte(`[]`))
	if empty.ContentState != "captured" || empty.EpochDigest != "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945" || empty.ToolDefinitions.Items == nil {
		t.Fatalf("lost explicit empty tool set: %+v", empty)
	}
	absent := contextCapture(t, contextMeta(t, ContextObservationToolDefinitions), nil)
	if absent.ContentState != "never_captured" || absent.ToolDefinitions != nil || absent.EpochDigest != "" {
		t.Fatalf("absence became an empty capture: %+v", absent)
	}
}

func TestContextObservationCapabilityProjection(t *testing.T) {
	captured := contextCapture(t, contextMeta(t, ContextObservationInstructions), []byte(`[{"type":"text","content":"safe"}]`))
	before, err := json.Marshal(captured)
	if err != nil {
		t.Fatal(err)
	}
	allowed := ProjectContextObservationContent(captured, true)
	restricted := ProjectContextObservationContent(captured, false)
	if !reflect.DeepEqual(allowed, captured) || restricted.ContentState != "permission_restricted" || restricted.ID != "synthetic-observation" || restricted.EpochDigest != captured.EpochDigest {
		t.Fatalf("capability projection changed metadata: %+v", restricted)
	}
	wire, err := json.Marshal(restricted)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"instructions":`, `"toolDefinitions":`, `"parts"`, `"items"`, `"safe"`} {
		if bytes.Contains(wire, []byte(key)) {
			t.Fatalf("restricted content key leaked: %s", wire)
		}
	}
	after, err := json.Marshal(captured)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("projection mutated observation: %s / %v", after, err)
	}
	tools := contextCapture(t, contextMeta(t, ContextObservationToolDefinitions), []byte(`[]`))
	if ProjectContextObservationContent(tools, false).ToolDefinitions != nil || ProjectContextObservationContent(tools, true).ToolDefinitions == nil {
		t.Fatal("tool capability projection is not content-only")
	}
	for _, unavailable := range contextFixture[[]ContextObservation](t, "unavailable") {
		restricted := ProjectContextObservationContent(unavailable, false)
		if restricted.ContentState != ContentPermissionRestricted || restricted.Source != unavailable.Source || restricted.SessionID != unavailable.SessionID {
			t.Fatal("unavailable projection changed source or associations")
		}
		data, err := json.Marshal(restricted)
		if err != nil {
			t.Fatal(err)
		}
		var decoded ContextObservation
		if err := json.Unmarshal(data, &decoded); err != nil || !reflect.DeepEqual(decoded, restricted) {
			t.Fatalf("unavailable capability projection is not a valid wire value: %s / %v", data, err)
		}
	}
}

func TestContextObservationConsecutiveEpochsAndAssociations(t *testing.T) {
	meta := contextMeta(t, ContextObservationInstructions)
	meta.NativeAttemptID, meta.ReviewID = "vendor-attempt", "review-link"
	a := contextCapture(t, meta, []byte(`[{"type":"text","content":"A"}]`))
	b := contextCapture(t, meta, []byte(`[{"type":"text","content":"B"}]`))
	var previous *ContextObservation
	var starts []bool
	for i, current := range []ContextObservation{a, a, b, a} {
		current.ID = fmt.Sprintf("observation-%d", i)
		current.NativeAttemptID = fmt.Sprintf("vendor-attempt-%d", i)
		current.ReviewID = fmt.Sprintf("review-%d", i)
		before, err := json.Marshal(current)
		if err != nil {
			t.Fatal(err)
		}
		starts = append(starts, ContextObservationStartsEpoch("default", previous, "default", current))
		after, err := json.Marshal(current)
		if err != nil || !bytes.Equal(before, after) || current.NativeAttemptID != fmt.Sprintf("vendor-attempt-%d", i) || current.ReviewID != fmt.Sprintf("review-%d", i) {
			t.Fatal("repeated content lost attempt/review association")
		}
		previous = &current
	}
	if !reflect.DeepEqual(starts, []bool{true, false, true, true}) {
		t.Fatalf("A,A,B,A epoch starts = %v", starts)
	}
	for name, change := range map[string]func(*ContextObservation){
		"instance": func(o *ContextObservation) { o.InstanceID = "other-instance" },
		"session":  func(o *ContextObservation) { o.SessionID = "other-session" },
		"adapter":  func(o *ContextObservation) { o.Source.Adapter = "pi" },
		"version":  func(o *ContextObservation) { o.Source.AdapterVersion = "other-version" },
		"hook":     func(o *ContextObservation) { o.Source.Hook = "other-hook" },
		"revision": func(o *ContextObservation) { o.Source.SourceRevision = "other-revision" },
		"kind":     func(o *ContextObservation) { o.Kind = ContextObservationToolDefinitions },
		"coverage": func(o *ContextObservation) { o.Coverage = ContextCoveragePrepared },
	} {
		t.Run(name, func(t *testing.T) {
			other := a
			change(&other)
			if !ContextObservationStartsEpoch("default", &a, "default", other) {
				t.Fatal("epoch identity ignored " + name)
			}
		})
	}
	if !ContextObservationStartsEpoch("other-tenant", &a, "default", a) {
		t.Fatal("server tenant missing from epoch identity")
	}
	omitted := contextCapture(t, meta, []byte(`[{"type":"text","content":"Bearer synthetic-canary"}]`))
	if !ContextObservationStartsEpoch("default", &omitted, "default", a) {
		t.Fatal("omitted to captured lost a new epoch")
	}
	tools := contextCapture(t, contextMeta(t, ContextObservationToolDefinitions), []byte(`[]`))
	if !ContextObservationStartsEpoch("default", &a, "default", b) || ContextObservationStartsEpoch("default", &tools, "default", tools) {
		t.Fatal("instruction change coupled the independent tool epoch")
	}
}

func TestContextObservationJudgeInputBytesUnchanged(t *testing.T) {
	e := engine(t)
	e.mu.Lock()
	e.Settings.Mode = "model"
	e.Settings.Model = ModelConfig{}
	e.mu.Unlock()
	args := map[string]any{"command": "printf observation-boundary", "options": map[string]any{"history": []any{"current-argument"}}}
	r, err := e.Submit(input("context-boundary", "context-fixture-tool", args))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"version":1,"hitlMode":"model","toolName":"context-fixture-tool","argumentsObj":{"command":"printf observation-boundary","options":{"history":["current-argument"]}}}`
	if string(r.ModelInput) != want || r.ModelContext == nil || *r.ModelContext != "" {
		t.Fatalf("Submit judge boundary = %s / %+v", r.ModelInput, r.ModelContext)
	}
	before, err := json.Marshal(modelInput(r))
	if err != nil || string(before) != want {
		t.Fatalf("judge bytes before observation = %s / %v", before, err)
	}
	for _, kind := range []ContextObservationKind{ContextObservationInstructions, ContextObservationToolDefinitions} {
		meta := contextMeta(t, kind)
		meta.ID, meta.InstanceID, meta.SessionID, meta.ReviewID = string(kind), r.InstanceID, r.SessionID, r.ID
		payload := []byte(`[{"type":"text","content":"excluded-observation-instruction"}]`)
		if kind == ContextObservationToolDefinitions {
			payload = []byte(`[{"type":"function","name":"excluded-observation-tool","parameters":{"description":"excluded-observation-schema"}}]`)
		}
		observation := contextCapture(t, meta, payload)
		if err := e.put("context_observation", observation.ID, observation); err != nil {
			t.Fatal(err)
		}
		var stored ContextObservation
		if err := e.get("context_observation", observation.ID, &stored); err != nil || !reflect.DeepEqual(stored, observation) {
			t.Fatalf("test observation was not stored: %+v / %v", stored, err)
		}
	}
	afterReview, err := e.Review(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(modelInput(afterReview))
	if err != nil || string(after) != want || !bytes.Equal(before, after) || !bytes.Equal(afterReview.ModelInput, r.ModelInput) || afterReview.ModelInputDigest != r.ModelInputDigest || afterReview.ModelContext == nil || *afterReview.ModelContext != "" {
		t.Fatalf("stored observations changed judge bytes: %s / %v", after, err)
	}
}
