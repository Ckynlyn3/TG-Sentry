package eval

import (
	"errors"
	"io"
)

// evaluate_prompted_agent.py main/predict_one_case: JSON rows, Tool Response.
// Filename establishes DH/DS and base/enhanced; never relabel from model outputs.
// https://github.com/uiuc-kang-lab/InjecAgent/blob/f19c9f2c79a41046eb13c03c51a24c567a8ffa07/src/evaluate_prompted_agent.py#L12-L47
func adaptInjecAgent(r io.Reader, s Dataset, f LockedFile) ([]Item, error) {
	switch f.Variant {
	case "dh-base", "ds-base", "dh-enhanced", "ds-enhanced":
	default:
		return nil, errors.New("InjecAgent requires frozen attack/setting variant")
	}
	return rowsToItems(r, s, f, "Tool Response", "tool_result", true)
}
