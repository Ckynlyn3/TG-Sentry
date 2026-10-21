package eval

import "io"

// PIGuard/eval.py NotInject_eval: native array of {prompt: string}, all benign.
// https://github.com/leolee99/PIGuard/blob/1b5751e88bf7475acbedfc8eda795ce060307c84/eval.py#L125-L160
func adaptNotInject(r io.Reader, s Dataset, f LockedFile) ([]Item, error) {
	return rowsToItems(r, s, f, "prompt", "prompt", false)
}
