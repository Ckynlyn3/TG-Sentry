package eval

import (
	"encoding/json"
	"errors"
	"io"
)

// Local synthetic records follow Presidio research's text+labelled-spans model;
// UTF-16 boundaries are the deployed BTPII contract (approved plan §1.1/§3).
type PIIRecord struct {
	ID       string   `json:"id"`
	Text     string   `json:"text"`
	Language string   `json:"language"`
	Surface  string   `json:"surface"`
	Entities []Entity `json:"entities"`
	Seed     string   `json:"seed"`
}

func adaptPII(r io.Reader, s Dataset, f LockedFile) ([]Item, error) {
	var rows []PIIRecord
	d := json.NewDecoder(r)
	if d.Decode(&rows) != nil || len(rows) == 0 || d.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid synthetic PII records")
	}
	out := make([]Item, 0, len(rows))
	for i, row := range rows {
		if row.Text == "" || (row.Surface != "prompt" && row.Surface != "tool_result") || (row.Language != "EN" && row.Language != "ZH") {
			return nil, errors.New("invalid synthetic PII schema")
		}
		if s.SplitUse == "dev" && row.Seed != "dev" {
			return nil, errors.New("non-dev seed in dev fixture")
		}
		if err := ValidateEntities(row.Text, row.Entities); err != nil {
			return nil, err
		}
		item := makeItem(s, f, i, row.Text, row.Surface, len(row.Entities) > 0, nil)
		item.Input.Language = row.Language
		item.Gold = row.Entities
		item.Seed = row.Seed
		out = append(out, item)
	}
	return out, nil
}
