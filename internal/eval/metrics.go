// Package eval implements the offline, pre-registered M3 evaluation protocol.
package eval

import (
	"errors"
	"math"
	"sort"
	"unicode/utf16"
	"unicode/utf8"
)

// Rate keeps the denominator even when the estimate is undefined (JSON null).
type Rate struct {
	Numerator int      `json:"numerator"`
	N         int      `json:"n"`
	Value     *float64 `json:"value"`
	Lower     *float64 `json:"wilson95_lower"`
	Upper     *float64 `json:"wilson95_upper"`
}

// Proportion uses the Wilson score interval (Brown, Cai & DasGupta 2001,
// Statistical Science 16(2), eq. 4); z is the standard normal 97.5% quantile.
func Proportion(k, n int) Rate {
	r := Rate{Numerator: k, N: n}
	if n <= 0 || k < 0 || k > n {
		return r
	}
	const z = 1.959963984540054
	p, nn := float64(k)/float64(n), float64(n)
	denom := 1 + z*z/nn
	center := (p + z*z/(2*nn)) / denom
	half := z * math.Sqrt(p*(1-p)/nn+z*z/(4*nn*nn)) / denom
	lo, hi := math.Max(0, center-half), math.Min(1, center+half)
	if k == 0 {
		lo = 0
	}
	if k == n {
		hi = 1
	}
	r.Value, r.Lower, r.Upper = &p, &lo, &hi
	return r
}

type Counts struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	FN int `json:"fn"`
	TN int `json:"tn"`
}

func (c Counts) Precision() Rate { return Proportion(c.TP, c.TP+c.FP) }
func (c Counts) Recall() Rate    { return Proportion(c.TP, c.TP+c.FN) }
func (c Counts) F1() *float64 {
	d := 2*c.TP + c.FP + c.FN
	if d == 0 {
		return nil
	}
	f := float64(2*c.TP) / float64(d)
	return &f
}

// NearestRank is sorted[ceil(p*n)-1], plan §3; no interpolation or mutation.
func NearestRank(values []float64, p float64) *float64 {
	if len(values) == 0 || !(p > 0 && p <= 1) {
		return nil
	}
	v := append([]float64(nil), values...)
	sort.Float64s(v)
	result := v[int(math.Ceil(p*float64(len(v))))-1]
	return &result
}
func WouldBlock(decision string) bool { return decision == "block" || decision == "reject" }

type Span struct {
	StartUTF16 int `json:"start_utf16"`
	EndUTF16   int `json:"end_utf16"`
}
type Entity struct {
	Type string `json:"type"`
	Span
}

func ValidateEntities(text string, entities []Entity) error {
	if !utf8.ValidString(text) {
		return errors.New("invalid UTF-8 text")
	}
	boundaries := map[int]bool{0: true}
	pos := 0
	for _, r := range text {
		pos += utf16.RuneLen(r)
		boundaries[pos] = true
	}
	for _, e := range entities {
		if e.Type == "" || e.StartUTF16 >= e.EndUTF16 || !boundaries[e.StartUTF16] || !boundaries[e.EndUTF16] {
			return errors.New("invalid UTF-16 entity boundary")
		}
	}
	return nil
}
func mappedType(t string, mapping map[string]string) string {
	if mapping == nil {
		return t
	}
	return mapping[t]
}
func ExactEntities(gold, pred []Entity, mapping map[string]string) Counts {
	c := Counts{}
	used := make([]bool, len(gold))
	for _, p := range pred {
		found := false
		for i, g := range gold {
			if !used[i] && mappedType(p.Type, mapping) == g.Type && p.Span == g.Span {
				used[i] = true
				found = true
				break
			}
		}
		if found {
			c.TP++
		} else {
			c.FP++
		}
	}
	c.FN = len(gold) - c.TP
	return c
}

// CharacterCounts unions labelled UTF-16 units per type (not rune/byte overlap).
// TG-Java char-F1 precedent is frozen in the approved plan §3/T7.
func CharacterCounts(gold, pred []Entity, mapping map[string]string, kind string) Counts {
	units := func(es []Entity, translate bool) map[int]bool {
		out := map[int]bool{}
		for _, e := range es {
			t := e.Type
			if translate {
				t = mappedType(t, mapping)
				if t == "" {
					t = "unmapped"
				}
			}
			if t == kind {
				for i := e.StartUTF16; i < e.EndUTF16; i++ {
					out[i] = true
				}
			}
		}
		return out
	}
	g, p := units(gold, false), units(pred, true)
	c := Counts{}
	for i := range p {
		if g[i] {
			c.TP++
		} else {
			c.FP++
		}
	}
	c.FN = len(g) - c.TP
	return c
}
