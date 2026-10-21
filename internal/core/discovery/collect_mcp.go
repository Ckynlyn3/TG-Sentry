package discovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"path"
	"slices"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"
)

// CollectMCP parses only local configuration; it never runs a command, expands
// env values or contacts a URL. Plan §3.5 (:56), sentinel cases §6 (:99).
func (r *HomeRoot) CollectMCP(ctx context.Context, paths AgentPaths, nodeID, accountID string) Category {
	c := collection("mcp", paths.Supported && len(paths.ConfigFiles) != 0)
	if c.ScanState == ScanNotSupported {
		return c
	}
	for _, rel := range paths.ConfigFiles {
		// cli-config.json is presence evidence, not Cursor's MCP configuration
		// (plan §3.3 :46). Honor an own-home root override without adding paths.
		if paths.Family == "cursor" && path.Base(rel) != "mcpServers.json" {
			continue
		}
		present, reason := r.collectionPath(ctx, rel)
		if reason != "" {
			return collectionFailure(c, reason)
		}
		if !present {
			continue
		}
		// S3 enforces ConfigParseBudgetBytes, named local exception §9.2 (:134).
		data, reason := r.ReadConfig(ctx, rel)
		if reason != "" {
			return collectionFailure(c, reason)
		}
		assets, reason := mcpAssets(ctx, data, rel, paths.Family, nodeID, accountID)
		c.Assets = append(c.Assets, assets...)
		if reason != "" {
			return collectionFailure(c, reason)
		}
	}
	return c
}

func mcpAssets(ctx context.Context, data []byte, rel, family, nodeID, accountID string) ([]Asset, Reason) {
	servers, reason := mcpServers(data, rel, family)
	if reason != "" {
		return nil, reason
	}
	var assets []Asset
	for _, name := range slices.Sorted(maps.Keys(servers)) {
		if ctx.Err() != nil {
			return assets, ReasonCanceled
		}
		descriptor, reason := mcpProjection(name, servers[name], family)
		if reason != "" {
			return assets, reason
		}
		id, err := AssetID(nodeID, accountID, family, "mcp", rel, name)
		if err != nil {
			return assets, ReasonUnparsedFormat
		}
		assets = append(assets, Asset{AssetID: id, Name: name, Category: "mcp", SourceRelPath: rel,
			Hash: descriptorHash(descriptor), HashKind: DescriptorSHA256, Descriptor: &descriptor})
	}
	if ctx.Err() != nil {
		return assets, ReasonCanceled
	}
	return assets, ""
}

// Malformed supported syntax is parse_failed; deferred formats/shapes are unparsed_format.
func mcpServers(data []byte, rel, family string) (map[string]any, Reason) {
	// OpenCode's distinct mcp schema stays deferred (plan OQ5 :125), even if
	// a stray mcpServers object is present; never authorize an empty replacement.
	if family == "opencode" {
		return nil, ReasonUnparsedFormat
	}
	var config map[string]any
	key := "mcpServers"
	switch path.Ext(rel) {
	case ".json":
		if !utf8.Valid(data) || !json.Valid(data) {
			return nil, ReasonParseFailed
		}
		// Vendor member names are case-sensitive, unlike S1 report struct fields.
		if checkMCPJSONValue(json.NewDecoder(bytes.NewReader(data)), data) != nil {
			return nil, ReasonParseFailed
		}
		if json.Unmarshal(data, &config) != nil {
			return nil, ReasonUnparsedFormat
		}
	case ".toml":
		if family != "codex" {
			return nil, ReasonUnparsedFormat
		}
		if toml.Unmarshal(data, &config) != nil {
			return nil, ReasonParseFailed
		}
		key = "mcp_servers"
		if _, exists := config[key]; !exists {
			return map[string]any{}, ""
		}
	default:
		// JSONC is deferred per plan §3.5/OQ5 (:56/:125), lead disposition;
		// no S4-supported family requires a comment-bearing JSON parser.
		return nil, ReasonUnparsedFormat
	}
	servers, ok := config[key].(map[string]any)
	if !ok || servers == nil {
		return nil, ReasonUnparsedFormat
	}
	return servers, ""
}

// RFC 8259 §4/§8.3: compare decoded object names exactly, without case folding.
// Reuse S1 checkedToken's Unicode safeguards; discard all source-bearing errors.
// json.Valid has already enforced syntax and encoding/json's nesting limit.
func checkMCPJSONValue(d *json.Decoder, data []byte) error {
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
			name := key.(string)
			if seen[name] {
				return ErrInvalidReport
			}
			seen[name] = true
			if err := checkMCPJSONValue(d, data); err != nil {
				return err
			}
		}
		_, err = d.Token()
	case json.Delim('['):
		for d.More() {
			if err := checkMCPJSONValue(d, data); err != nil {
				return err
			}
		}
		_, err = d.Token()
	}
	return err
}

// Documented schema only: MCP "Configure the Filesystem Server"
// https://modelcontextprotocol.io/docs/develop/connect-local-servers#installing-the-filesystem-server
// and JSON transport type/headers: https://code.claude.com/docs/en/mcp#add-mcp-servers-from-json-configuration .
// Codex command/url/env/http_headers: https://developers.openai.com/codex/mcp ;
// https://github.com/openai/codex/blob/main/codex-rs/core/config.schema.json .
// No analyst-inferred Claude/OpenCode key names (plan OQ5 :125).
func mcpProjection(name string, value any, family string) (MCPDescriptor, Reason) {
	entry, ok := value.(map[string]any)
	if !ok || entry == nil || name == "" || !validStrings(name) {
		return MCPDescriptor{}, ReasonUnparsedFormat
	}
	transport, reason := mcpTransport(entry, family)
	if reason != "" {
		return MCPDescriptor{}, reason
	}
	if _, reason := mcpStrings(entry, "args"); reason != "" {
		return MCPDescriptor{}, reason
	}
	env, reason := mcpEnvironmentKeys(entry, family)
	if reason != "" {
		return MCPDescriptor{}, reason
	}
	headers, reason := mcpHeaderKeys(entry, family)
	if reason != "" {
		return MCPDescriptor{}, reason
	}
	return MCPDescriptor{Name: name, Transport: transport, EnvKeys: env, HeaderKeys: headers}, ""
}

func mcpTransport(entry map[string]any, family string) (string, Reason) {
	command, hasCommand := entry["command"]
	url, hasURL := entry["url"]
	if hasCommand == hasURL {
		return "", ReasonUnparsedFormat
	}
	transport := "stdio"
	if hasCommand {
		if text, ok := command.(string); !ok || text == "" {
			return "", ReasonUnparsedFormat
		}
	} else {
		if text, ok := url.(string); !ok || text == "" {
			return "", ReasonUnparsedFormat
		}
		transport = "http"
	}
	if family != "codex" {
		if declared, exists := entry["type"]; exists && declared != transport {
			if declared != "sse" || !hasURL {
				return "", ReasonUnparsedFormat
			}
			transport = "sse"
		}
	}
	return transport, ""
}

func mcpKeys(entry map[string]any, field string) ([]string, Reason) {
	value, exists := entry[field]
	if !exists {
		return []string{}, ""
	}
	values, ok := value.(map[string]any)
	if !ok || values == nil {
		return nil, ReasonUnparsedFormat
	}
	for key, value := range values {
		if _, ok := value.(string); !ok || !validStrings(key) {
			return nil, ReasonUnparsedFormat
		}
	}
	keys := slices.AppendSeq([]string{}, maps.Keys(values))
	slices.Sort(keys)
	return keys, ""
}

func mcpStrings(entry map[string]any, field string) ([]string, Reason) {
	value, exists := entry[field]
	if !exists {
		return []string{}, ""
	}
	values, ok := value.([]any)
	if !ok {
		return nil, ReasonUnparsedFormat
	}
	strings := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok || !validStrings(text) {
			return nil, ReasonUnparsedFormat
		}
		strings = append(strings, text)
	}
	return strings, ""
}

// Codex also documents pass-through env_vars and env_http_headers mappings at
// https://developers.openai.com/codex/mcp#configure-mcp-servers . Values in the
// latter are variable references, not header names; never include them.
func mcpEnvironmentKeys(entry map[string]any, family string) ([]string, Reason) {
	keys, reason := mcpKeys(entry, "env")
	if reason != "" || family != "codex" {
		return keys, reason
	}
	passed, reason := mcpStrings(entry, "env_vars")
	if reason != "" {
		return nil, reason
	}
	return sortedMCPKeys(keys, passed), ""
}

func mcpHeaderKeys(entry map[string]any, family string) ([]string, Reason) {
	if family != "codex" {
		return mcpKeys(entry, "headers")
	}
	keys, reason := mcpKeys(entry, "http_headers")
	if reason != "" {
		return nil, reason
	}
	passed, reason := mcpKeys(entry, "env_http_headers")
	if reason != "" {
		return nil, reason
	}
	return sortedMCPKeys(keys, passed), ""
}

func sortedMCPKeys(left, right []string) []string {
	keys := append(slices.Clone(left), right...)
	slices.Sort(keys)
	return slices.Compact(keys)
}

// Sorted-key Go JSON over the projection only (plan :27/:56). This fingerprint
// is not configuration integrity proof, authentication, or anonymization.
func descriptorHash(d MCPDescriptor) string {
	data, _ := json.Marshal(map[string]any{"name": d.Name, "transport": d.Transport,
		"envKeys": d.EnvKeys, "headerKeys": d.HeaderKeys})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
