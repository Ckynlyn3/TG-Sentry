package eval

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

func Adapt(r io.Reader, s Dataset, f LockedFile) ([]Item, error) {
	switch s.Name {
	case "AgentDojo":
		return adaptAgentDojo(r, s, f)
	case "InjecAgent":
		return adaptInjecAgent(r, s, f)
	case "NotInject":
		return adaptNotInject(r, s, f)
	case "CPAD", "MCPSecBench", "ZH-BENIGN-LOCAL":
		return adaptMapped(r, s, f)
	case "PII-dev", "PII-acceptance":
		return adaptPII(r, s, f)
	case "R-Judge", "PINT":
		return nil, errors.New("dataset not admissible")
	default:
		return nil, errors.New("unknown adapter")
	}
}
func language(s Dataset, row map[string]any) string {
	if s.LanguageMetadataLevel == "set" && len(s.Languages) == 1 {
		return s.Languages[0]
	}
	if s.LanguageMetadataLevel == "item" && s.FieldMap != nil && s.FieldMap.Language != "" {
		if v, ok := row[s.FieldMap.Language].(string); ok {
			switch strings.ToLower(v) {
			case "en", "english":
				return "EN"
			case "zh", "chinese":
				return "ZH"
			}
		}
	}
	return "mixed/unknown"
}
func textField(row map[string]any, key string) (string, error) {
	text, ok := row[key].(string)
	if !ok || strings.TrimSpace(text) == "" {
		return "", errors.New("missing or invalid text field")
	}
	return text, nil
}
func makeItem(s Dataset, f LockedFile, index int, text, surface string, positive bool, row map[string]any) Item {
	// Opaque IDs avoid leaking text in upstream ids/paths. Ordinals are stable;
	// sorting occurs once across the entire set, never sampling.
	id := Digest([]any{s.Name, f.Path, f.Member, f.Variant, index})
	return Item{ID: id, Positive: positive, Input: Input{Text: text, Surface: surface, Language: language(s, row), Tenant: "eval"}, Variant: f.Variant}
}
func readRows(r io.Reader, format string) ([]map[string]any, error) {
	switch format {
	case "json":
		var rows []map[string]any
		d := json.NewDecoder(r)
		if d.Decode(&rows) != nil || rows == nil {
			return nil, errors.New("expected JSON row array")
		}
		if d.Decode(new(any)) != io.EOF {
			return nil, errors.New("trailing JSON")
		}
		return rows, nil
	case "jsonl":
		// Decoder, not Scanner: no invented line-length limit; one object per line.
		return readJSONLines(r)
	case "csv":
		d := csv.NewReader(r)
		header, e := d.Read()
		if e != nil {
			return nil, errors.New("missing CSV header")
		}
		seen := map[string]bool{}
		for _, k := range header {
			if k == "" || seen[k] {
				return nil, errors.New("duplicate or empty CSV column")
			}
			seen[k] = true
		}
		rows := []map[string]any{}
		for {
			cells, e := d.Read()
			if e == io.EOF {
				break
			}
			if e != nil {
				return nil, errors.New("invalid CSV row")
			}
			row := map[string]any{}
			for i, k := range header {
				row[k] = cells[i]
			}
			rows = append(rows, row)
		}
		return rows, nil
	default:
		return nil, errors.New("unsupported row format")
	}
}
func adaptMapped(r io.Reader, s Dataset, f LockedFile) ([]Item, error) {
	m := s.FieldMap
	if m == nil {
		return nil, errors.New("schema pending")
	}
	if m.Text == "" || m.Category != s.Category || (m.Surface != "prompt" && m.Surface != "tool_result" && m.Surface != "file") {
		return nil, errors.New("invalid field map")
	}
	if (s.Name == "CPAD" && !m.Label) || (s.Name == "ZH-BENIGN-LOCAL" && m.Label) {
		return nil, errors.New("field map contradicts benchmark labels")
	}
	rows, e := readRows(r, m.Format)
	if e != nil {
		return nil, e
	}
	items := make([]Item, 0, len(rows))
	for i, row := range rows {
		text, e := textField(row, m.Text)
		if e != nil {
			return nil, e
		}
		items = append(items, makeItem(s, f, i, text, m.Surface, m.Label, row))
	}
	return items, nil
}
func rowsToItems(r io.Reader, s Dataset, f LockedFile, key, surface string, label bool) ([]Item, error) {
	rows, e := readRows(r, "json")
	if e != nil {
		return nil, e
	}
	out := make([]Item, 0, len(rows))
	for i, row := range rows {
		text, e := textField(row, key)
		if e != nil {
			return nil, fmt.Errorf("row %d: invalid schema", i)
		}
		out = append(out, makeItem(s, f, i, text, surface, label, row))
	}
	return out, nil
}

func readJSONLines(r io.Reader) ([]map[string]any, error) {
	d := bufio.NewReader(r)
	rows := []map[string]any{}
	for {
		line, e := d.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			var row map[string]any
			if json.Unmarshal(line, &row) != nil || row == nil {
				return nil, errors.New("invalid JSONL row")
			}
			rows = append(rows, row)
		}
		if e == io.EOF {
			return rows, nil
		}
		if e != nil {
			return nil, errors.New("cannot read JSONL")
		}
	}
}
