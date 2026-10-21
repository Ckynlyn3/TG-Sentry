package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	ErrToolOutputOversized = errors.New("tool output JSON exceeds bridge envelope")
	ErrToolOutputTrailing  = errors.New("tool output JSON contains trailing data")
	errToolOutputJSON      = errors.New("invalid tool output JSON")
)

func ReadToolOutputJSON(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, ToolOutputJSONBytes+1))
	if err != nil {
		return nil, errToolOutputJSON
	}
	if len(data) > ToolOutputJSONBytes {
		return nil, ErrToolOutputOversized
	}
	return data, nil
}
func toolOutputFields(data []byte, allowed ...string) (map[string]json.RawMessage, error) {
	if len(data) > ToolOutputJSONBytes {
		return nil, ErrToolOutputOversized
	}
	if !validToolOutputUnicode(data) {
		return nil, errToolOutputJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var value json.RawMessage
	if decoder.Decode(&value) != nil {
		return nil, errToolOutputJSON
	}
	if decoder.Decode(&value) != io.EOF {
		return nil, ErrToolOutputTrailing
	}
	var fields map[string]json.RawMessage
	if DecodeReviewJSON(data, &fields) != nil || fields == nil {
		return nil, errToolOutputJSON
	}
	for key := range fields {
		if !hasExact(key, allowed...) {
			return nil, errToolOutputJSON
		}
	}
	return fields, nil
}
func DecodeToolOutputRequest(data []byte) (ToolOutputRequest, error) {
	fields, err := toolOutputFields(data, "operation", "text")
	var request ToolOutputRequest
	if err != nil {
		return request, err
	}
	if len(fields) != 2 || !toolOutputString(fields["operation"], &request.Operation) || !toolOutputString(fields["text"], &request.Text) || request.Operation != "transform_tool_output" {
		return ToolOutputRequest{}, errToolOutputJSON
	}
	return request, nil
}
func DecodeToolOutputResponse(data []byte) (ToolOutputResponse, error) {
	fields, err := toolOutputFields(data, "outcome", "text")
	var response ToolOutputResponse
	if err != nil {
		return response, err
	}
	if !toolOutputString(fields["outcome"], &response.Outcome) {
		return response, errToolOutputJSON
	}
	switch response.Outcome {
	case "unchanged", "unavailable":
		if len(fields) != 1 {
			return ToolOutputResponse{}, errToolOutputJSON
		}
	case "rewritten", "withheld":
		var text string
		if len(fields) != 2 || !toolOutputString(fields["text"], &text) || response.Outcome == "withheld" && text != ToolOutputWithheld {
			return ToolOutputResponse{}, errToolOutputJSON
		}
		response.Text = &text
	default:
		return ToolOutputResponse{}, errToolOutputJSON
	}
	return response, nil
}
func toolOutputString(raw json.RawMessage, out *string) bool {
	return len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, out) == nil
}

// RFC 8259 §§8.1–8.2: reject invalid UTF-8 and unpaired UTF-16 escapes,
// which encoding/json otherwise replaces silently with U+FFFD. Escaped literal
// backslashes are skipped, so a text value containing "\\ud800" stays valid.
func validToolOutputUnicode(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		unit, ok := toolOutputUnit(data, i)
		if !ok {
			return false
		}
		i += 4 // JSON unicode escape is exactly four hexadecimal digits (RFC 8259 §7).
		if !utf16.IsSurrogate(unit) {
			continue
		}
		next := i + 1
		if next+1 >= len(data) || data[next] != '\\' || data[next+1] != 'u' {
			return false
		}
		low, ok := toolOutputUnit(data, next+1)
		if !ok || utf16.DecodeRune(unit, low) == utf8.RuneError {
			return false
		}
		i = next + 5
	}
	return true
}
func toolOutputUnit(data []byte, index int) (rune, bool) {
	if index+4 >= len(data) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(data[index+1:index+5]), 16, 16)
	return rune(n), err == nil
}
