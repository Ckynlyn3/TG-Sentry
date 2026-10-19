package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Contract source: TG-Java/trust-gateway/deploy/nsfa-guard/openapi.yaml:83-209.
// Config paths contain no secrets; the integration layer supplies loaded auth and
// the frozen identity to NewNSFAClient. Enforce availability gating belongs there.
type NSFAConfig struct {
	DeclaredLambda     float64 `json:"declaredLambda,omitempty"`
	FrozenConfigSHA256 string  `json:"frozenConfigSHA256,omitempty"`
	Endpoint           string  `json:"endpoint"`
	TokenFile          string  `json:"tokenFile"`
	IdentityFile       string  `json:"identityFile"`
	Mode               string  `json:"mode"`
	ResponseHead       bool    `json:"responseHead"`
}

// NSFAAuth is ephemeral and must not enter settings, events, or error messages.
type NSFAAuth struct {
	Token              string `json:"-"`
	WorkloadIdentity   string `json:"-"`
	WorkloadCredential string `json:"-"`
}

type NSFARequest struct {
	Text      string `json:"text"`
	Task      string `json:"task"`
	RequestID string `json:"request_id,omitempty"`
}

type NSFAHead struct {
	Task   string `json:"task"`
	SHA256 string `json:"sha256"`
}

type NSFAIdentity struct {
	Model          string              `json:"model"`
	ModelRevision  string              `json:"model_revision"`
	ManifestSHA256 string              `json:"manifest_sha256"`
	Representation string              `json:"representation"`
	Heads          map[string]NSFAHead `json:"heads"`
	Thresholds     map[string]float64  `json:"thresholds"`
}

type NSFAResponse struct {
	Verdict    string             `json:"verdict"`
	Task       string             `json:"task"`
	Fired      map[string]float64 `json:"fired"`
	Probs      map[string]float64 `json:"probs"`
	Thresholds map[string]float64 `json:"thresholds"`
	LatencyMS  int64              `json:"latency_ms"`
	Identity   NSFAIdentity       `json:"identity"`
}

const (
	nsfaModel          = "inclusionAI/SingGuard-NSFA-0.8B"
	nsfaRevision       = "455a72e4331b9ef37ae49154eff2a3715642c17a"
	nsfaRepresentation = "readme_untrusted_v1"
	// Issue #21 plan §4: port NsfaGuardClient.java:45-48,425-453.
	nsfaFailureThreshold = 2
	nsfaCooldown         = 15 * time.Second
	nsfaMaxResponseBytes = 2 * 1024 * 1024
	nsfaMaxRequestID     = 128
)

var (
	nsfaHeads = []string{"Prompt_Injection_and_Jailbreak", "Malicious_Code_and_Cyberattack", "Dangerous_Operations_Tool_Abuse", "Hazardous_Action_Generation"}
	nsfaHash  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// NsfaGuardClient.java:50-51 workload credential syntax.
	nsfaWorkload = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	nsfaToken    = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)
)

// NSFAClient never authorizes: it returns source findings for effective-rule
// attribution by the detector. Breaker state is protected; I/O never holds mu.
type NSFAClient struct {
	config     NSFAConfig
	auth       NSFAAuth
	expected   NSFAIdentity
	http       *http.Client
	now        func() time.Time
	configured bool
	mu         sync.Mutex
	state      string
	generation uint64
	openedAt   time.Time
	active     int
	failures   int
	tooLarge   uint64
}

// NSFAStats separates input-budget rejection from sidecar/breaker failures.
type NSFAStats struct {
	State         string
	InputTooLarge uint64
}

func NewNSFAClient(config NSFAConfig, auth NSFAAuth, expected NSFAIdentity) *NSFAClient {
	expected.Heads = maps.Clone(expected.Heads)
	expected.Thresholds = maps.Clone(expected.Thresholds)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // Same-host only; Java client:100-101 refuses proxies/redirects.
	return &NSFAClient{config: config, auth: auth, expected: expected, now: time.Now, state: "closed",
		configured: nsfaAllowedEndpoint(config.Endpoint) && (config.Mode == "monitor" || config.Mode == "enforce") &&
			nsfaToken.MatchString(auth.Token) && nsfaWorkload.MatchString(auth.WorkloadIdentity) && nsfaWorkload.MatchString(auth.WorkloadCredential) && nsfaValidIdentity(expected),
		http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func nsfaAllowedEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(endpoint, "#") || (u.Path != "" && u.Path != "/") {
		return false
	}
	if !slices.Contains([]string{"localhost", "127.0.0.1", "::1"}, strings.ToLower(u.Hostname())) {
		return false
	}
	if port := u.Port(); port != "" {
		p, err := strconv.ParseUint(port, 10, 16)
		return err == nil && p > 0
	}
	return !strings.HasSuffix(u.Host, ":")
}

func nsfaHeadTask(head string) string {
	if head == nsfaHeads[3] {
		return "response"
	}
	return "query"
}

func nsfaTaskHeads(task string) []string {
	if task == "response" {
		return nsfaHeads[3:]
	}
	return nsfaHeads[:3]
}

func nsfaValidIdentity(identity NSFAIdentity) bool {
	if identity.Model != nsfaModel || identity.ModelRevision != nsfaRevision || identity.Representation != nsfaRepresentation || !nsfaHash.MatchString(identity.ManifestSHA256) || len(identity.Heads) != len(nsfaHeads) || len(identity.Thresholds) != len(nsfaHeads) {
		return false
	}
	for _, head := range nsfaHeads {
		value := identity.Heads[head]
		if value.Task != nsfaHeadTask(head) || !nsfaHash.MatchString(value.SHA256) || identity.Thresholds[head] != 0.5 {
			return false
		}
	}
	return true
}

func (c *NSFAClient) Stats() NSFAStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return NSFAStats{State: c.state, InputTooLarge: c.tooLarge}
}

// Classify propagates the caller's remaining deadline unchanged (plan §10 H3;
// https://grpc.io/docs/guides/deadlines/#deadline-propagation). No fresh budget.
func (c *NSFAClient) Classify(ctx context.Context, text, task, requestID string) PromptAttackResult {
	if !c.configured {
		return nsfaUnavailable("nsfa_not_configured")
	}
	if text == "" || !utf8.ValidString(text) || !utf8.ValidString(requestID) || utf8.RuneCountInString(requestID) > nsfaMaxRequestID || (task != "query" && task != "response") {
		return nsfaUnavailable("nsfa_invalid_input")
	}
	if task == "response" && !c.config.ResponseHead {
		return nsfaUnavailable("nsfa_response_disabled")
	}
	if ctx.Err() != nil {
		return nsfaContextFailure(ctx, ctx.Err())
	}
	generation, reason := c.admit()
	if reason != "" {
		return nsfaUnavailable(reason)
	}
	result := c.classify(ctx, NSFARequest{Text: text, Task: task, RequestID: requestID})
	c.complete(generation, result)
	return result
}

func (c *NSFAClient) classify(ctx context.Context, input NSFARequest) PromptAttackResult {
	data, _ := json.Marshal(input)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.config.Endpoint, "/")+"/classify", bytes.NewReader(data))
	if err != nil {
		return nsfaUnavailable("nsfa_not_configured")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.auth.Token)
	request.Header.Set("X-TG-Workload-Identity", c.auth.WorkloadIdentity)
	request.Header.Set("X-TG-Workload-Credential", c.auth.WorkloadCredential)
	response, err := c.http.Do(request)
	if err != nil {
		return nsfaContextFailure(ctx, err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusRequestEntityTooLarge {
		return nsfaUnavailable("nsfa_413")
	}
	if response.StatusCode != http.StatusOK {
		return nsfaUnavailable("nsfa_unavailable")
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, nsfaMaxResponseBytes+1))
	if err != nil {
		return nsfaContextFailure(ctx, err)
	}
	if ctx.Err() != nil {
		return nsfaContextFailure(ctx, ctx.Err())
	}
	if len(data) > nsfaMaxResponseBytes {
		return nsfaUnavailable("nsfa_invalid_verdict")
	}
	verdict, ok := c.validate(data, input.Task)
	if !ok {
		return nsfaUnavailable("nsfa_invalid_verdict")
	}
	result := PromptAttackResult{}
	// Fixed head order makes evidence deterministic, independent of JSON map order.
	for _, head := range nsfaTaskHeads(input.Task) {
		if score, fired := verdict.Fired[head]; fired {
			tag := map[string]string{nsfaHeads[0]: "default-prompt-injection", nsfaHeads[1]: "remote-code-execution", nsfaHeads[3]: "inducing-harmful-content"}[head]
			result.Evidence = append(result.Evidence, PromptAttackEvidence{Type: "nsfa:" + head, Head: head, Tag: tag, Score: score})
			if tag != "" {
				result.Findings = append(result.Findings, PromptAttackFinding{Category: "category::prompt-attack", Tag: tag, Type: "nsfa:" + head, Score: score})
			}
		}
	}
	return result
}

func nsfaUnavailable(reason string) PromptAttackResult {
	return PromptAttackResult{Unavailable: true, Reason: reason}
}

func nsfaContextFailure(ctx context.Context, err error) PromptAttackResult {
	if ctx.Err() == context.Canceled {
		return nsfaUnavailable("nsfa_canceled")
	}
	if ctx.Err() == context.DeadlineExceeded || errors.Is(err, context.DeadlineExceeded) {
		return nsfaUnavailable("nsfa_timeout")
	}
	return nsfaUnavailable("nsfa_unavailable")
}

// Port of NsfaGuardClient.java:425-463, including generation fencing: an old
// in-flight completion cannot close/reset a newer OPEN or HALF_OPEN generation.
func (c *NSFAClient) admit() (uint64, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == "open" {
		if c.now().Sub(c.openedAt) < nsfaCooldown {
			return 0, "nsfa_breaker"
		}
		c.transition("half_open")
	}
	if c.state == "half_open" && c.active != 0 {
		return 0, "nsfa_breaker"
	}
	if c.state == "closed" && c.active >= nsfaFailureThreshold {
		return 0, "nsfa_busy"
	}
	c.active++
	return c.generation, ""
}

func (c *NSFAClient) complete(generation uint64, result PromptAttackResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if result.Reason == "nsfa_413" {
		c.tooLarge++
	}
	if generation != c.generation {
		return
	}
	c.active--
	if result.Reason == "nsfa_413" {
		return
	}
	if result.Unavailable {
		c.failures++
		if c.state == "half_open" || c.failures >= nsfaFailureThreshold {
			c.openedAt = c.now()
			c.transition("open")
		}
	} else {
		c.failures = 0
		if c.state == "half_open" {
			c.transition("closed")
		}
	}
}

func (c *NSFAClient) transition(state string) { c.state = state; c.generation++; c.active = 0 }

// Exact Java verdict/identity checks: NsfaGuardClient.java:297-339. In particular,
// plan §10 M5 forbids re-thresholding fired's rounded wire values (0.5 is valid).
func (c *NSFAClient) validate(data []byte, task string) (NSFAResponse, bool) {
	var response NSFAResponse
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := nsfaJSONValue(dec)
	if err != nil {
		return response, false
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return response, false
	}
	root, _ := value.(map[string]any)
	if !nsfaKeys(root, "verdict", "task", "fired", "probs", "thresholds", "latency_ms", "identity") {
		return response, false
	}
	identity, _ := root["identity"].(map[string]any)
	if !nsfaKeys(identity, "model", "model_revision", "manifest_sha256", "representation", "heads", "thresholds") {
		return response, false
	}
	heads, _ := identity["heads"].(map[string]any)
	if !nsfaKeys(heads, nsfaHeads...) {
		return response, false
	}
	for _, head := range nsfaHeads {
		metadata, _ := heads[head].(map[string]any)
		if !nsfaKeys(metadata, "task", "sha256") {
			return response, false
		}
	}
	wanted := nsfaTaskHeads(task)
	if !nsfaNumbers(root["probs"], wanted, true, false) || !nsfaNumbers(root["fired"], wanted, false, false) || !nsfaNumbers(root["thresholds"], wanted, true, true) || !nsfaNumbers(identity["thresholds"], nsfaHeads, true, true) {
		return response, false
	}
	if json.Unmarshal(data, &response) != nil || root["latency_ms"] == nil || response.LatencyMS < 0 || response.Task != task || (response.Verdict != "safe" && response.Verdict != "unsafe") || (response.Verdict == "safe") != (len(response.Fired) == 0) {
		return response, false
	}
	return response, reflect.DeepEqual(response.Identity, c.expected)
}

func nsfaKeys(object map[string]any, keys ...string) bool {
	if object == nil || len(object) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
}

func nsfaProbability(p float64) bool { return !math.IsNaN(p) && !math.IsInf(p, 0) && p >= 0 && p <= 1 }

func nsfaNumbers(value any, heads []string, exact, threshold bool) bool {
	object, ok := value.(map[string]any)
	if !ok || (exact && !nsfaKeys(object, heads...)) {
		return false
	}
	for key, value := range object {
		number, ok := value.(json.Number)
		p, err := number.Float64()
		if !ok || err != nil || !slices.Contains(heads, key) || !nsfaProbability(p) || (threshold && p != 0.5) {
			return false
		}
	}
	return true
}

// Java uses STRICT_DUPLICATE_DETECTION + FAIL_ON_TRAILING_TOKENS (:61-62).
// Read objects with stdlib tokens so duplicate keys at any depth cannot vanish
// during map/struct decoding. Arrays are not part of this response contract.
func nsfaJSONValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('{') {
		if _, delimiter := token.(json.Delim); delimiter {
			return nil, errors.New("nsfa_invalid_verdict")
		}
		return token, nil
	}
	object := map[string]any{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if _, duplicate := object[name]; !ok || duplicate {
			return nil, errors.New("nsfa_invalid_verdict")
		}
		value, err := nsfaJSONValue(dec)
		if err != nil {
			return nil, err
		}
		object[name] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return object, nil
}
