package eval

import (
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
)

// TraceLogger.save writes injections, messages and attack_type to a JSON trace.
// https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/logging.py#L202-L262
// Only the injected slots are positives, not every tool message in an attack
// run. Clean traces must have no attack metadata. Utility/ASR are NOT recall.
func adaptAgentDojo(r io.Reader, s Dataset, f LockedFile) ([]Item, error) {
	var trace struct {
		Injections map[string]string `json:"injections"`
		Messages   []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		AttackType      *string `json:"attack_type"`
		InjectionTaskID *string `json:"injection_task_id"`
	}
	d := json.NewDecoder(r)
	if d.Decode(&trace) != nil || d.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid AgentDojo trace")
	}
	out := []Item{}
	switch f.Variant {
	case "attack":
		if trace.AttackType == nil || trace.InjectionTaskID == nil || len(trace.Injections) == 0 {
			return nil, errors.New("missing injected-slot labels")
		}
		keys := []string{}
		for k := range trace.Injections {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if trace.Injections[k] == "" {
				return nil, errors.New("empty injection")
			}
			out = append(out, makeItem(s, f, i, trace.Injections[k], "tool_result", true, nil))
		}
	case "clean":
		if trace.AttackType != nil || trace.InjectionTaskID != nil || len(trace.Injections) != 0 {
			return nil, errors.New("attack trace cannot be labelled clean")
		}
		for i, msg := range trace.Messages {
			if msg.Role == "tool" {
				text, err := agentDojoText(msg.Content)
				if err != nil {
					return nil, err
				}
				out = append(out, makeItem(s, f, i, text, "tool_result", false, nil))
			}
		}
	default:
		return nil, errors.New("AgentDojo requires frozen clean/attack variant")
	}
	if len(out) == 0 {
		return nil, errors.New("empty AgentDojo input")
	}
	return out, nil
}

// ChatToolResultMessage.content is list[MessageContentBlock] at the pinned
// revision. Match get_text_content_as_str: join every non-null content value
// with a newline, including thinking blocks and empty strings.
// https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/types.py
func agentDojoText(raw json.RawMessage) (string, error) {
	var blocks []struct {
		Type    string          `json:"type"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &blocks) != nil || blocks == nil {
		return "", errors.New("invalid tool content blocks")
	}
	parts := []string{}
	for _, block := range blocks {
		switch block.Type {
		case "text", "thinking", "redacted_thinking":
		default:
			return "", errors.New("invalid tool content block type")
		}
		if len(block.Content) == 0 {
			return "", errors.New("tool content block missing content")
		}
		if string(block.Content) == "null" {
			continue
		}
		var text string
		if json.Unmarshal(block.Content, &text) != nil {
			return "", errors.New("invalid tool content block value")
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, "\n"), nil
}
