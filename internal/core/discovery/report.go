// Package discovery defines the metadata-only discovery/v1 endpoint contract.
package discovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const SchemaVersion = "discovery/v1"

// ConfigParseBudgetBytes is a provisional named local resource budget (plan R7).
// Named local exception: time and memory will be measured in S4.
const ConfigParseBudgetBytes = 2 << 20

// DirectoryEntryBudget is a provisional per-directory resource budget (plan R7).
// Named local exception: time and memory will be measured in S4. Not a report cap.
const DirectoryEntryBudget = 1024

// ReportScope selects which device-local accounts the endpoint observes.
type ReportScope string

const (
	OwnHome          ReportScope = "own_home"
	AllLocalAccounts ReportScope = "all_local_accounts"
)

type HomeState string

const (
	HomeReadable    HomeState = "readable"
	HomeDenied      HomeState = "denied"
	HomeUnavailable HomeState = "unavailable"
)

// FoundState is a tri-state observation, not a protection or identity claim.
type FoundState string

const (
	Found        FoundState = "found"
	NotFound     FoundState = "not_found"
	FoundUnknown FoundState = "unknown"
)

type Scope string

const (
	ScopeHome       Scope = "home"
	ScopeProject    Scope = "project"
	ScopeAutoMemory Scope = "auto_memory"
)

type ScanState string

const (
	ScanNotSupported ScanState = "not_supported"
	ScanNotScanned   ScanState = "not_scanned"
	ScanScanned      ScanState = "scanned"
	ScanError        ScanState = "error"
	ScanUnknown      ScanState = "unknown"
)

// Reason is closed: errors never carry config text, content or secret values.
type Reason string

const (
	ReasonProjectScopeDeferred Reason = "project_scope_deferred"
	ReasonUnreadable           Reason = "unreadable"
	ReasonNotRegularFile       Reason = "not_regular_file"
	ReasonEscapedRoot          Reason = "escaped_root"
	ReasonParseFailed          Reason = "parse_failed"
	ReasonTooLarge             Reason = "too_large"
	ReasonTooManyEntries       Reason = "too_many_entries"
	ReasonChangedDuringRead    Reason = "changed_during_read"
	ReasonCanceled             Reason = "canceled"
	ReasonUnparsedFormat       Reason = "unparsed_format"
	ReasonTGTargetOnly         Reason = "tg_target_only"
	ReasonHomeDenied           Reason = "home_denied"
	ReasonHomeUnavailable      Reason = "home_unavailable"
	ReasonOwnerMismatch        Reason = "owner_mismatch"
)

type HashKind string

const (
	FileSHA256       HashKind = "file_sha256"
	DescriptorSHA256 HashKind = "descriptor_sha256"
)

type Report struct {
	SchemaVersion   string      `json:"schemaVersion"`
	NodeID          string      `json:"nodeId"`
	Scope           ReportScope `json:"scope"`
	Mode            string      `json:"mode"`
	Final           bool        `json:"final"`
	ScanStartedAt   time.Time   `json:"scanStartedAt"`
	ScanCompletedAt time.Time   `json:"scanCompletedAt"`
	Accounts        []Account   `json:"accounts"`
}

type Account struct {
	ObservedLocalAccount string    `json:"observedLocalAccount"`
	AccountID            string    `json:"accountId"`
	HomePath             string    `json:"homePath"`
	HomeState            HomeState `json:"homeState"`
	Agents               []Agent   `json:"agents"`
}

type Agent struct {
	Family     string     `json:"family"`
	Found      FoundState `json:"found"`
	Evidence   Evidence   `json:"evidence"`
	Version    string     `json:"version"`
	Categories []Category `json:"categories"`
}

type Evidence struct {
	Kind    string     `json:"kind"`
	RelPath string     `json:"relPath"`
	Mtime   *time.Time `json:"mtime,omitempty"`
}

// Category state belongs to (Category, Scope), not Category alone.
type Category struct {
	Category  string    `json:"category"`
	Scope     Scope     `json:"scope"`
	ScanState ScanState `json:"scanState"`
	Reason    Reason    `json:"reason,omitempty"`
	Assets    []Asset   `json:"assets"`
}

type Asset struct {
	AssetID       string         `json:"assetId"`
	Name          string         `json:"name"`
	Category      string         `json:"category"`
	SourceRelPath string         `json:"sourceRelPath"`
	Size          *int64         `json:"size,omitempty"`
	Mtime         *time.Time     `json:"mtime,omitempty"`
	Hash          string         `json:"hash"`
	HashKind      HashKind       `json:"hashKind"`
	Descriptor    *MCPDescriptor `json:"descriptor,omitempty"`
}

// MCPDescriptor is exactly the allowed projection, not the vendor configuration.
// Its hash is a projection fingerprint, not integrity proof or anonymization.
type MCPDescriptor struct {
	Name       string   `json:"name"`
	Transport  string   `json:"transport"`
	EnvKeys    []string `json:"envKeys"`
	HeaderKeys []string `json:"headerKeys"`
}

var (
	ErrInvalidReport  = errors.New("invalid discovery report")
	ErrDuplicateAsset = errors.New("duplicate_asset")
)

// DecodeReport accepts one discovery/v1 report, with no unknown fields at any
// depth or trailing data. Callers enforce their own transport body limit (LD9).
// Static errors deliberately exclude parser messages containing source data.
func DecodeReport(r io.Reader) (Report, error) {
	var report Report
	data, err := io.ReadAll(r)
	if err != nil {
		return Report{}, decodeError{cause: err}
	}
	// json.Valid also applies encoding/json's native nesting-depth guard before
	// the token walk, so deeply nested hostile JSON cannot grow our call stack.
	if !utf8.Valid(data) || !json.Valid(data) {
		return Report{}, ErrInvalidReport
	}
	// The transport caller bounds these bytes. Token validates original strings
	// before encoding/json can silently replace lone surrogates (RFC 7493 §2.1).
	prepass := json.NewDecoder(bytes.NewReader(data))
	prepass.UseNumber()
	if err := checkJSONValue(prepass, data); err != nil {
		return Report{}, decodeError{cause: err}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&report); err != nil {
		return Report{}, decodeError{cause: err}
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return Report{}, decodeError{cause: err}
	}
	if err := report.Validate(); err != nil {
		return Report{}, err
	}
	return report, nil
}

// Preserve transport causes (for example body-limit errors) for errors.Is/As,
// without exposing parser messages through Error(). Do not log unwrapped causes.
type decodeError struct{ cause error }

func (e decodeError) Error() string        { return ErrInvalidReport.Error() }
func (e decodeError) Unwrap() error        { return e.cause }
func (e decodeError) Is(target error) bool { return target == ErrInvalidReport }

// Validate enforces Unicode, v1 enums, wire paths and unique state/asset keys. Node
// authorization, timestamp ordering and reconciliation belong to server ingest.
func (r Report) Validate() error {
	if !validStrings(r.NodeID) || r.SchemaVersion != SchemaVersion || r.Mode != "full" || !r.Final ||
		(r.Scope != OwnHome && r.Scope != AllLocalAccounts) {
		return ErrInvalidReport
	}
	seen := make(map[string]bool)
	for _, account := range r.Accounts {
		if !validStrings(account.ObservedLocalAccount, account.AccountID, account.HomePath) ||
			(account.HomeState != HomeReadable && account.HomeState != HomeDenied && account.HomeState != HomeUnavailable) {
			return ErrInvalidReport
		}
		for _, agent := range account.Agents {
			if !validStrings(agent.Family, agent.Evidence.Kind, agent.Evidence.RelPath) ||
				agent.Version != "unknown" || (agent.Found != Found && agent.Found != NotFound && agent.Found != FoundUnknown) {
				return ErrInvalidReport
			}
			states := make(map[[2]string]bool)
			for _, category := range agent.Categories {
				key := [2]string{category.Category, string(category.Scope)}
				if states[key] {
					return ErrInvalidReport
				}
				states[key] = true
				if err := category.validate(seen); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (c Category) validate(seen map[string]bool) error {
	if !validCategory(c.Category) || (c.Scope != ScopeHome && c.Scope != ScopeProject && c.Scope != ScopeAutoMemory) {
		return ErrInvalidReport
	}
	switch c.ScanState {
	case ScanNotSupported, ScanNotScanned, ScanScanned, ScanError, ScanUnknown:
	default:
		return ErrInvalidReport
	}
	switch c.Reason {
	case "", ReasonProjectScopeDeferred, ReasonUnreadable, ReasonNotRegularFile,
		ReasonEscapedRoot, ReasonParseFailed, ReasonTooLarge, ReasonTooManyEntries,
		ReasonChangedDuringRead, ReasonCanceled, ReasonUnparsedFormat,
		ReasonTGTargetOnly, ReasonHomeDenied, ReasonHomeUnavailable, ReasonOwnerMismatch:
	default:
		return ErrInvalidReport
	}
	for _, asset := range c.Assets {
		if !validStrings(asset.AssetID, asset.Name, asset.SourceRelPath, asset.Hash) ||
			!validCategory(asset.Category) || !validSourcePath(asset.SourceRelPath) ||
			(asset.HashKind != FileSHA256 && asset.HashKind != DescriptorSHA256) {
			return ErrInvalidReport
		}
		if d := asset.Descriptor; d != nil && (!validStrings(d.Name, d.Transport) ||
			!validStrings(d.EnvKeys...) || !validStrings(d.HeaderKeys...)) {
			return ErrInvalidReport
		}
		if seen[asset.AssetID] {
			return ErrDuplicateAsset
		}
		seen[asset.AssetID] = true
	}
	return nil
}

func validCategory(category string) bool {
	switch category {
	case "skills", "mcp", "plugins", "builtin_tools", "memory":
		return true
	}
	return false
}

func validSourcePath(path string) bool {
	// fs.ValidPath accepts backslash/colon; the wire format does not use host OS
	// normalization. Explicitly disallow Windows drive prefixes (plan §3.2).
	return fs.ValidPath(path) && path != "." && !strings.ContainsAny(path, "\\\x00") &&
		!(len(path) >= 2 && path[1] == ':' && ((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z')))
}

func validStrings(values ...string) bool {
	for _, value := range values {
		if !utf8.ValidString(value) {
			return false
		}
	}
	return true
}

// checkJSONValue rejects duplicate unescaped, case-folded member names, matching
// encoding/json's EqualFold field matching (Go src/encoding/json/fold.go).
func checkJSONValue(d *json.Decoder, data []byte) error {
	token, err := checkedToken(d, data)
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for d.More() {
			key, err := checkedToken(d, data)
			if err != nil {
				return err
			}
			name := foldMemberName(key.(string))
			if seen[name] {
				return ErrInvalidReport
			}
			seen[name] = true
			if err := checkJSONValue(d, data); err != nil {
				return err
			}
		}
		_, err = d.Token()
	case json.Delim('['):
		for d.More() {
			if err := checkJSONValue(d, data); err != nil {
				return err
			}
		}
		_, err = d.Token()
	}
	return err
}

func foldMemberName(name string) string {
	return strings.Map(func(r rune) rune {
		for next := unicode.SimpleFold(r); next > r; next = unicode.SimpleFold(r) {
			r = next
		}
		return unicode.SimpleFold(r)
	}, name)
}

func checkedToken(d *json.Decoder, data []byte) (json.Token, error) {
	start := d.InputOffset()
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	if s, ok := token.(string); ok && (!utf8.ValidString(s) || !validEscapes(data[start:d.InputOffset()])) {
		return nil, ErrInvalidReport
	}
	return token, nil
}

// Token has already checked JSON syntax, including hex digits. Inspect original
// escapes so legitimate U+FFFD (literal or escaped) remains distinguishable from
// encoding/json's replacement of invalid UTF-16 (RFC 8259 §8.2).
func validEscapes(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		n, _ := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if len(raw) <= i+6 || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, _ := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
