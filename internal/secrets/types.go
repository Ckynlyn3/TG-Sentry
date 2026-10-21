// Package secrets detects the frozen Gitleaks rule subset without retaining
// candidate material in findings.
package secrets

// Status distinguishes a complete clean scan from an unavailable/partial scan.
type Status string

const (
	Complete    Status = "Complete"
	Interrupted Status = "Interrupted"
)

// Span uses UTF-16 code units in the original field, with an exclusive end.
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Finding contains metadata only, never the value, match or source line.
// RuleID stays in-process; wire locations identify the frozen entity type.
type Finding struct {
	RuleID     string `json:"-"`
	EntityType string `json:"entity_type"`
	Span       Span   `json:"span"`
}

// Leaf locates a finding in an original map key or string value. Path is for
// in-memory omission only; serialization emits its SHA-256 digest instead.
type Leaf struct {
	Finding
	Surface     string `json:"surface"`
	Kind        string `json:"kind"`
	FieldDigest string `json:"field_digest"`
	Path        string `json:"-"`
}
