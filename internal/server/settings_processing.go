package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// The rest of PUT settings keeps its existing decoding compatibility. Only this
// new input object is strict; saved actor/timestamp fields are never writable.
type settingsProcessingInput struct {
	Enabled bool `json:"enabled"`
}

func (in *settingsProcessingInput) UnmarshalJSON(data []byte) error {
	type input settingsProcessingInput
	var value input
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("invalid external-processing input")
	}
	*in = settingsProcessingInput(value)
	return nil
}
