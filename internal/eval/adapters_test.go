package eval

import (
	"context"
	"strings"
	"testing"
)

func TestNativeAdaptersSyntheticOnly(t *testing.T) {
	for _, tc := range []struct {
		name, data, variant, surface string
		label                        bool
		n                            int
	}{
		{"NotInject", `[{"prompt":"FAKE synthetic benign record"}]`, "one", "prompt", false, 1},
		{"InjecAgent", `[{"Tool Response":"FAKE synthetic tool result","User Instruction":"FAKE task"}]`, "dh-base", "tool_result", true, 1},
		{"AgentDojo", `{"suite_name":"fake","user_task_id":"fake-user","injection_task_id":"fake-attack","attack_type":"fake","injections":{"fake-slot":"FAKE synthetic injected result"},"messages":[]}`, "attack", "tool_result", true, 1},
		{"AgentDojo", `{"suite_name":"fake","user_task_id":"fake-user","injection_task_id":null,"attack_type":null,"injections":{},"messages":[{"role":"tool","content":[{"type":"text","content":"FAKE clean result"}],"error":null}]}`, "clean", "tool_result", false, 1},
	} {
		t.Run(tc.name+tc.variant, func(t *testing.T) {
			s := Dataset{Name: tc.name, Category: "category::prompt-attack", LanguageMetadataLevel: "none"}
			got, e := Adapt(strings.NewReader(tc.data), s, LockedFile{Path: "fake", Variant: tc.variant})
			if e != nil || len(got) != tc.n {
				t.Fatal(got, e)
			}
			if got[0].Positive != tc.label || got[0].Input.Surface != tc.surface || got[0].Input.Language != "mixed/unknown" {
				t.Fatal(got[0])
			}
		})
	}
}
func TestMappedAdaptersFailClosedAndReadAllFormats(t *testing.T) {
	for _, format := range []string{"json", "jsonl", "csv"} {
		s := Dataset{Name: "CPAD", Category: "category::prompt-attack", Languages: []string{"ZH"}, LanguageMetadataLevel: "set"}
		if _, e := Adapt(strings.NewReader(`[]`), s, LockedFile{}); e == nil {
			t.Fatal("schema pending accepted")
		}
		s.FieldMap = &FieldMap{Format: format, Text: "fake_text", Language: "fake_lang", Label: true, Category: s.Category, Surface: "prompt"}
		data := map[string]string{"json": `[{"fake_text":"SYNTHETIC NOT A BENCHMARK ITEM","fake_lang":"ZH"}]`, "jsonl": "{\"fake_text\":\"SYNTHETIC NOT A BENCHMARK ITEM\",\"fake_lang\":\"ZH\"}\n", "csv": "fake_text,fake_lang\nSYNTHETIC NOT A BENCHMARK ITEM,ZH\n"}[format]
		items, e := Adapt(strings.NewReader(data), s, LockedFile{Path: "fake"})
		if e != nil || len(items) != 1 || !items[0].Positive {
			t.Fatal(items, e)
		}
	}
	for _, name := range []string{"PINT", "R-Judge", "unknown"} {
		if _, e := Adapt(strings.NewReader(`[]`), Dataset{Name: name}, LockedFile{}); e == nil {
			t.Fatal("unlicensed/unknown adapter accepted")
		}
	}
}
func TestAdapterInvalidInputAndNoop(t *testing.T) {
	for _, data := range []string{`null`, `{}`, `[{"prompt":null}]`, `[{"prompt":17}]`, `[{"prompt":"fake"}] []`} {
		if _, e := Adapt(strings.NewReader(data), Dataset{Name: "NotInject"}, LockedFile{}); e == nil {
			t.Fatal(data)
		}
	}
	got, e := (noopDetector{}).Detect(context.Background(), Input{Text: "FAKE"})
	if e != nil || !got.Unavailable || got.Reason == "" {
		t.Fatal(got, e)
	}
}
