package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type schemaAttribute struct {
	Type        string                     `json:"type"`
	Requirement string                     `json:"requirement"`
	ObjectType  string                     `json:"object_type"`
	IsArray     bool                       `json:"is_array"`
	Enum        map[string]json.RawMessage `json:"enum"`
}
type eventSchema struct {
	Attributes map[string]schemaAttribute `json:"attributes"`
	Required   []string                   `json:"required"`
}

func pinnedEventSchemas(t *testing.T) map[string]eventSchema {
	t.Helper()
	root := filepath.Join("testdata", "event-schema")
	b, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Fixtures []struct{ File, Source, SHA256 string }
	}
	if err = json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	schemas := map[string]eventSchema{}
	for _, fixture := range manifest.Fixtures {
		b, err := os.ReadFile(filepath.Join(root, fixture.File))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != fixture.SHA256 {
			t.Fatalf("schema hash mismatch: %s", fixture.File)
		}
		if fixture.Source == "" {
			t.Fatal("schema source missing")
		}
		var schema eventSchema
		if err = json.Unmarshal(b, &schema); err != nil {
			t.Fatal(err)
		}
		schemas[fixture.File[:len(fixture.File)-len(".json")]] = schema
	}
	return schemas
}
func validateOCSFObject(schemas map[string]eventSchema, name string, value map[string]any) error {
	schema, ok := schemas[name]
	if !ok {
		return fmt.Errorf("unpinned object %s", name)
	}
	for key, attribute := range schema.Attributes {
		if attribute.Requirement == "required" {
			if _, ok := value[key]; !ok {
				return fmt.Errorf("missing %s.%s", name, key)
			}
		}
	}
	for key, item := range value {
		attribute, ok := schema.Attributes[key]
		if !ok {
			return fmt.Errorf("unknown %s.%s", name, key)
		}
		items := []any{item}
		if attribute.IsArray {
			var ok bool
			items, ok = item.([]any)
			if !ok {
				return fmt.Errorf("%s is not an array", key)
			}
		}
		for _, child := range items {
			if err := validateOCSFValue(schemas, attribute, child); err != nil {
				return fmt.Errorf("%s.%s: %w", name, key, err)
			}
		}
	}
	return nil
}
func validateOCSFValue(schemas map[string]eventSchema, attribute schemaAttribute, value any) error {
	switch attribute.Type {
	case "object_t":
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("expected object")
		}
		if attribute.ObjectType != "" && attribute.ObjectType != "object" {
			return validateOCSFObject(schemas, attribute.ObjectType, object)
		}
	case "integer_t", "long_t", "timestamp_t":
		number, ok := value.(float64)
		if !ok || math.Trunc(number) != number {
			return fmt.Errorf("expected integer")
		}
		if len(attribute.Enum) > 0 {
			if _, ok = attribute.Enum[strconv.FormatFloat(number, 'f', 0, 64)]; !ok {
				return fmt.Errorf("invalid enum")
			}
		}
	case "string_t":
		text, ok := value.(string)
		if !ok || text == "" {
			return fmt.Errorf("expected nonempty string")
		}
	case "json_t":
		if _, ok := value.(map[string]any); !ok {
			return fmt.Errorf("expected JSON object")
		}
	default:
		return fmt.Errorf("unhandled pinned attribute type %s", attribute.Type)
	}
	return nil
}
func requiredEventStrings(value map[string]any, keys ...string) error {
	for _, key := range keys {
		if text, ok := value[key].(string); !ok || text == "" {
			return fmt.Errorf("missing string %s", key)
		}
	}
	return nil
}
func validateEventWire(schemas map[string]eventSchema, event map[string]any) error {
	if err := validateNoSecretStrings(event); err != nil {
		return err
	}
	required := append(append([]string{}, schemas["cloudevents"].Required...), "time", "datacontenttype")
	if err := requiredEventStrings(event, required...); err != nil {
		return err
	}
	if event["specversion"] != "1.0" || event["datacontenttype"] != "application/json" {
		return fmt.Errorf("invalid CE constants")
	}
	if len(event) != 7 {
		return fmt.Errorf("unexpected CE context attributes")
	}
	source, err := url.Parse(event["source"].(string))
	if err != nil || source.User != nil || source.RawQuery != "" || source.Fragment != "" {
		return fmt.Errorf("unsafe source")
	}
	at, err := time.Parse(time.RFC3339Nano, event["time"].(string))
	if err != nil {
		return err
	}
	data, ok := event["data"].(map[string]any)
	if !ok {
		return fmt.Errorf("missing object data")
	}
	name := "detection_finding"
	if event["type"] == "tg.sentry.audit.v1" {
		name = "api_activity"
	} else if event["type"] != "tg.sentry.risk.v1" {
		return fmt.Errorf("invalid event type")
	}
	if err = validateOCSFObject(schemas, name, data); err != nil {
		return err
	}
	if data["time"] != float64(at.UnixMilli()) || data["type_uid"] != data["class_uid"].(float64)*100+data["activity_id"].(float64) {
		return fmt.Errorf("time/type mismatch")
	}
	return validateLocalEvent(event, data)
}
func validateLocalEvent(event, data map[string]any) error {
	metadata, ok := data["metadata"].(map[string]any)
	if !ok {
		return fmt.Errorf("missing metadata")
	}
	if err := requiredEventStrings(metadata, "uid", "version", "tenant_uid", "correlation_uid"); err != nil {
		return err
	}
	product, ok := metadata["product"].(map[string]any)
	if !ok || product["name"] != "TG-Sentry" || metadata["version"] != "1.9.0" || metadata["uid"] != event["id"] {
		return fmt.Errorf("metadata constants or identity mismatch")
	}
	actor, ok := data["actor"].(map[string]any)
	if !ok {
		return fmt.Errorf("missing actor")
	}
	unmapped, ok := data["unmapped"].(map[string]any)
	if !ok || len(unmapped) != 1 {
		return fmt.Errorf("invalid extensions")
	}
	extension, ok := unmapped["tg_sentry"].(map[string]any)
	if !ok {
		return fmt.Errorf("missing tg_sentry")
	}
	if err := validateEventExtension(extension); err != nil {
		return err
	}
	if err := validateEventIdentity(event, data, actor, extension); err != nil {
		return err
	}
	if actor["app_uid"] == nil && extension["identity_state"] != "unenrolled" {
		return fmt.Errorf("missing enrolled identity or explicit local exception")
	}
	if state, ok := extension["identity_state"]; ok && (state != "unenrolled" || actor["app_uid"] != nil) {
		return fmt.Errorf("invalid identity state")
	}
	if event["type"] == "tg.sentry.risk.v1" {
		return validateLocalRisk(data)
	}
	if data["class_uid"] != float64(6003) || data["category_uid"] != float64(6) || data["activity_id"] != float64(99) || data["severity_id"] != float64(1) {
		return fmt.Errorf("invalid audit classification")
	}
	if !hasExact(fmt.Sprint(data["activity_name"]), "Tool Call Request", "Tool Call Result", "Prompt Turn Request", "Prompt Turn Result") || extension["content_state"] != "omitted" {
		return fmt.Errorf("invalid audit observation/content state")
	}
	if data["action_id"] != nil || metadata["profiles"] != nil {
		return fmt.Errorf("unused audit profiles/control")
	}
	endpoint, ok := data["src_endpoint"].(map[string]any)
	if !ok || (endpoint["uid"] == nil && extension["identity_state"] != "unenrolled") {
		return fmt.Errorf("missing endpoint")
	}
	return nil
}
func validateLocalRisk(data map[string]any) error {
	if data["class_uid"] != float64(2004) || data["category_uid"] != float64(2) || (data["activity_id"] != float64(1) && data["activity_id"] != float64(2)) {
		return fmt.Errorf("invalid risk classification")
	}
	if data["activity_id"] == float64(2) && (data["action_id"] != float64(2) || data["disposition_id"] != float64(2)) {
		return fmt.Errorf("invalid confirmed-block update")
	}
	if !hasExact(fmt.Sprint(data["severity_id"]), "0", "2", "3", "4", "5") {
		return fmt.Errorf("invalid risk severity")
	}
	action, disposition := fmt.Sprint(data["action_id"]), fmt.Sprint(data["disposition_id"])
	if !hasExact(action+"/"+disposition, "0/0", "2/2", "3/17", "3/19", "3/15") {
		return fmt.Errorf("invalid handling pair")
	}
	metadata := data["metadata"].(map[string]any)
	profiles, ok := metadata["profiles"].([]any)
	if !ok || len(profiles) != 2 || profiles[0] != "security_control" || profiles[1] != "host" {
		return fmt.Errorf("invalid risk profiles")
	}
	finding := data["finding_info"].(map[string]any)
	if values, ok := finding["types"].([]any); ok {
		for _, value := range values {
			if !validRiskCategory(fmt.Sprint(value)) {
				return fmt.Errorf("invalid protection category")
			}
		}
	}
	return nil
}
func wireEvent(t *testing.T, event Event) map[string]any {
	t.Helper()
	b, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err = json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	return wire
}
func TestPinnedEventSchemaRequiredFieldsAndEnums(t *testing.T) {
	schemas := pinnedEventSchemas(t)
	e := engine(t)
	rejected, err := e.Submit(input("finding", "Bash", map[string]any{"command": "redis-cli FLUSHALL"}))
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := e.Submit(input("clean", "Read", map[string]any{"file_path": "fixture"}))
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Result(allowed.ID, "instance", "failed", "nested raw-content-canary"); err != nil {
		t.Fatal(err)
	}
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	var risk Event
	for _, audit := range audits {
		for _, event := range audit.Events {
			if err := validateEventWire(schemas, wireEvent(t, event)); err != nil {
				t.Fatalf("%s: %v", event.Type, err)
			}
			if event.Type == "tg.sentry.risk.v1" {
				risk = event
			}
		}
	}
	if risk.Data.FindingInfo.UID != rejected.ID {
		t.Fatal("risk missing")
	}
	for _, path := range [][]string{{"id"}, {"source"}, {"type"}, {"specversion"}, {"time"}, {"datacontenttype"}, {"data"}, {"data", "actor"}, {"data", "action_id"}, {"data", "disposition_id"}, {"data", "metadata", "tenant_uid"}, {"data", "metadata", "correlation_uid"}, {"data", "metadata", "uid"}, {"data", "metadata", "version"}, {"data", "metadata", "product"}, {"data", "finding_info", "uid"}, {"data", "unmapped", "tg_sentry", "identity_state"}} {
		wire := wireEvent(t, risk)
		object := wire
		for _, key := range path[:len(path)-1] {
			object = object[key].(map[string]any)
		}
		delete(object, path[len(path)-1])
		if err := validateEventWire(schemas, wire); err == nil {
			t.Fatalf("missing %v accepted", path)
		}
	}
	for _, tc := range []struct {
		key   string
		value any
	}{{"class_uid", 6003.0}, {"type_uid", 200402.0}, {"severity_id", 1.0}, {"severity_id", 999.0}, {"activity_id", 4.0}, {"action_id", 99.0}, {"disposition_id", 99.0}, {"time", 1.0}} {
		wire := wireEvent(t, risk)
		wire["data"].(map[string]any)[tc.key] = tc.value
		if err := validateEventWire(schemas, wire); err == nil {
			t.Fatalf("bad %s accepted", tc.key)
		}
	}
}

func TestEnrolledAlertAndAuditObservationSchema(t *testing.T) {
	schemas := pinnedEventSchemas(t)
	e := engine(t)
	code, err := e.CreateEnrollment(testActorContext(), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := e.EnrollClient(code.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Register(Instance{ID: "remote", NodeID: connection.NodeID, Agent: "claude", Platform: "linux", SessionID: "session", Cwd: "/work", HookVersion: Version}); err != nil {
		t.Fatal(err)
	}
	rule := Rule{ID: "U_ALERT", Name: "fixture", Decision: "alert", Enabled: true, Tool: "fixture", Pattern: "fixture", Severity: "critical", Categories: []string{"category::high-risk-ops"}}
	if err = e.SaveRule(testActorContext(), rule); err != nil {
		t.Fatal(err)
	}
	r, err := e.Submit(ReviewInput{InstanceID: "remote", CallID: "call", ToolName: "fixture", Arguments: map[string]any{"value": "fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Result(r.ID, "remote", "succeeded", "content-canary"); err != nil {
		t.Fatal(err)
	}
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	observations := map[string]Event{}
	for _, audit := range audits {
		for _, event := range audit.Events {
			if err = validateEventWire(schemas, wireEvent(t, event)); err != nil {
				t.Fatal(event.Type, err)
			}
			if ids[event.ID] {
				t.Fatal("occurrence ID reused")
			}
			ids[event.ID] = true
			if event.Type == "tg.sentry.audit.v1" {
				observations[event.Data.ActivityName] = event
			}
		}
	}
	if len(ids) != 3 || len(observations) != 2 {
		t.Fatal("missing request/result/finding", ids)
	}
	for name, event := range observations {
		if event.Data.API.Request.UID != "call" || event.Data.SrcEndpoint.UID != connection.NodeID {
			t.Fatal(event)
		}
		if name == "Tool Call Request" && *event.Data.StatusID != 0 {
			t.Fatal("approval treated as execution")
		}
		wire := wireEvent(t, event)
		data := wire["data"].(map[string]any)
		delete(data["api"].(map[string]any), "operation")
		if validateEventWire(schemas, wire) == nil {
			t.Fatal("missing operation accepted")
		}
		wire = wireEvent(t, event)
		data = wire["data"].(map[string]any)
		delete(data["api"].(map[string]any)["request"].(map[string]any), "uid")
		if validateEventWire(schemas, wire) == nil {
			t.Fatal("missing request UID accepted")
		}
		wire = wireEvent(t, event)
		data = wire["data"].(map[string]any)
		data["unmapped"].(map[string]any)["tg_sentry"].(map[string]any)["content_state"] = "raw"
		if validateEventWire(schemas, wire) == nil {
			t.Fatal("raw content state accepted")
		}
	}
	page, err := e.RiskEvents(1, "", RiskEventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	wire := wireEvent(t, page.Items[0])
	finding := wire["data"].(map[string]any)["finding_info"].(map[string]any)
	delete(finding["analytic"].(map[string]any), "type_id")
	if validateEventWire(schemas, wire) == nil {
		t.Fatal("missing analytic type enum accepted")
	}
	for _, pair := range [][2]int{{0, 0}, {2, 2}, {3, 17}, {3, 19}, {3, 15}} {
		event := page.Items[0]
		event.Data.EventControl = &EventControl{ActionID: pair[0], DispositionID: pair[1]}
		if err = validateEventWire(schemas, wireEvent(t, event)); err != nil {
			t.Fatal(pair, err)
		}
	}
}

// The projection has no secret-bearing free text, including optional OCSF fields.
func validateNoSecretStrings(value any) error {
	switch value := value.(type) {
	case string:
		if RedactText(value) != value {
			return fmt.Errorf("detected secret or oversized text in telemetry")
		}
	case map[string]any:
		for _, child := range value {
			if err := validateNoSecretStrings(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := validateNoSecretStrings(child); err != nil {
				return err
			}
		}
	}
	return nil
}
func validateEventExtension(extension map[string]any) error {
	for key, value := range extension {
		text, ok := value.(string)
		if !ok || text == "" {
			return fmt.Errorf("extension must be a nonempty string")
		}
		switch key {
		case "content_state":
			if !hasExact(text, "omitted", "redacted") {
				return fmt.Errorf("invalid content state")
			}
		case "identity_state":
			if text != "unenrolled" {
				return fmt.Errorf("invalid identity state")
			}
		case "tool_call_id":
			if !eventIdentifierPattern.MatchString(text) {
				return fmt.Errorf("unsafe tool call identifier")
			}
		default:
			return fmt.Errorf("non-allowlisted extension")
		}
	}
	return nil
}
func validateEventIdentity(event, data, actor, extension map[string]any) error {
	endpoint, _ := data["src_endpoint"].(map[string]any)
	if extension["identity_state"] == "unenrolled" {
		if event["source"] != "/control-plane" || actor["app_uid"] != nil || endpoint["uid"] != nil {
			return fmt.Errorf("invented identity for unenrolled event")
		}
		return nil
	}
	appUID, ok := actor["app_uid"].(string)
	if !ok {
		return fmt.Errorf("missing enrolled app UID")
	}
	parts := strings.Split(appUID, "/")
	if len(parts) != 2 || parts[1] == "" || AgentName(parts[1]) == "" {
		return fmt.Errorf("invalid protected-agent identity")
	}
	node, err := hex.DecodeString(parts[0])
	if err != nil || len(node) != 16 {
		return fmt.Errorf("invalid enrolled node identity")
	}
	if event["source"] != "/endpoints/"+parts[0] {
		return fmt.Errorf("source differs from enrolled identity")
	}
	if endpoint != nil && endpoint["uid"] != parts[0] {
		return fmt.Errorf("source endpoint differs from enrolled identity")
	}
	return nil
}
