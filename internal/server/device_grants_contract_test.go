package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"mime"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

type deviceWireSchema struct {
	Ref        string                      `json:"$ref"`
	Type       deviceWireType              `json:"type"`
	Required   []string                    `json:"required"`
	Properties map[string]deviceWireSchema `json:"properties"`
	Additional *bool                       `json:"additionalProperties"`
	Enum       []any                       `json:"enum"`
	Const      any                         `json:"const"`
	Minimum    *float64                    `json:"minimum"`
	MinLength  *int                        `json:"minLength"`
	Pattern    string                      `json:"pattern"`
	Format     string                      `json:"format"`
	Encoding   string                      `json:"contentEncoding"`
	Items      *deviceWireSchema           `json:"items"`
	AnyOf      []deviceWireSchema          `json:"anyOf"`
	MinItems   *int                        `json:"minItems"`
	MaxItems   *int                        `json:"maxItems"`
}

// deviceWireType accepts the OpenAPI 3.1 type-array form used elsewhere in the
// document (for example ["string", "null"]). Arrays are kept as their raw text,
// so validating such a schema falls to the unsupported-type error.
type deviceWireType string

func (t *deviceWireType) UnmarshalJSON(data []byte) error {
	var single string
	if json.Unmarshal(data, &single) == nil {
		*t = deviceWireType(single)
		return nil
	}
	var union []string
	if err := json.Unmarshal(data, &union); err != nil {
		return err
	}
	*t = deviceWireType(string(data))
	return nil
}

type deviceWireResponse struct {
	Ref     string `json:"$ref"`
	Content map[string]struct {
		Schema deviceWireSchema `json:"schema"`
	} `json:"content"`
	Headers map[string]json.RawMessage `json:"headers"`
}
type deviceWireSpec struct {
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Components struct {
		Schemas   map[string]deviceWireSchema   `json:"schemas"`
		Responses map[string]deviceWireResponse `json:"responses"`
	} `json:"components"`
}

func deviceSpec(t *testing.T) deviceWireSpec {
	t.Helper()
	data, err := os.ReadFile("../../docs/design/protection.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec deviceWireSpec
	if err = json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	return spec
}

// Port the existing core/event_schema_test.go required-field/type/enum checks
// to the frozen OpenAPI response schemas, and add their explicit constraints.
// This is a bounded assertion helper for the device schemas, not a complete
// OpenAPI/JSON Schema validator; references resolve only within this document.
func deviceWireValidate(spec deviceWireSpec, schema deviceWireSchema, value any) error {
	if schema.Ref != "" {
		prefix := "#/components/schemas/"
		resolved, ok := spec.Components.Schemas[strings.TrimPrefix(schema.Ref, prefix)]
		if !strings.HasPrefix(schema.Ref, prefix) || !ok {
			return fmt.Errorf("unknown local schema reference")
		}
		return deviceWireValidate(spec, resolved, value)
	}
	if len(schema.AnyOf) > 0 {
		for _, branch := range schema.AnyOf {
			if deviceWireValidate(spec, branch, value) == nil {
				return nil
			}
		}
		return fmt.Errorf("no anyOf branch matches")
	}
	if schema.Type == "null" {
		if value != nil {
			return fmt.Errorf("expected null")
		}
		return nil
	}
	if schema.Const != nil && !reflect.DeepEqual(value, schema.Const) {
		return fmt.Errorf("const mismatch")
	}
	if len(schema.Enum) > 0 {
		found := false
		for _, item := range schema.Enum {
			found = found || reflect.DeepEqual(item, value)
		}
		if !found {
			return fmt.Errorf("enum mismatch")
		}
	}
	switch schema.Type {
	case "object":
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("expected object")
		}
		for _, field := range schema.Required {
			if _, ok := object[field]; !ok {
				return fmt.Errorf("missing required %s", field)
			}
		}
		for field, item := range object {
			property, known := schema.Properties[field]
			if !known {
				if schema.Additional != nil && !*schema.Additional {
					return fmt.Errorf("unexpected field %s", field)
				}
				continue
			}
			if err := deviceWireValidate(spec, property, item); err != nil {
				return fmt.Errorf("%s: %w", field, err)
			}
		}
	case "string":
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("expected string")
		}
		if schema.MinLength != nil && utf8.RuneCountInString(text) < *schema.MinLength {
			return fmt.Errorf("string shorter than minLength")
		}
		if schema.Pattern != "" && !regexp.MustCompile(schema.Pattern).MatchString(text) {
			return fmt.Errorf("pattern mismatch")
		}
		if schema.Format == "uri" {
			u, err := url.Parse(text)
			if err != nil || !u.IsAbs() {
				return fmt.Errorf("invalid absolute URI")
			}
		}
		if schema.Encoding == "base64" {
			if _, err := base64.StdEncoding.DecodeString(text); err != nil {
				return fmt.Errorf("invalid base64")
			}
		}
	case "integer":
		number, ok := value.(float64)
		if !ok || math.Trunc(number) != number || (schema.Minimum != nil && number < *schema.Minimum) {
			return fmt.Errorf("invalid integer")
		}
	case "array":
		items, ok := value.([]any)
		if !ok || (schema.MinItems != nil && len(items) < *schema.MinItems) || (schema.MaxItems != nil && len(items) > *schema.MaxItems) {
			return fmt.Errorf("invalid array")
		}
		if schema.Items == nil {
			return fmt.Errorf("missing item schema")
		}
		for _, item := range items {
			if err := deviceWireValidate(spec, *schema.Items, item); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported schema type %q", schema.Type)
	}
	return nil
}

func deviceContractResponse(t *testing.T, path string, w *httptest.ResponseRecorder) {
	t.Helper()
	spec := deviceSpec(t)
	var operation struct {
		Responses map[string]deviceWireResponse `json:"responses"`
	}
	if err := json.Unmarshal(spec.Paths[path]["post"], &operation); err != nil {
		t.Fatal(err)
	}
	response, ok := operation.Responses[strconv.Itoa(w.Code)]
	if !ok {
		t.Fatalf("%s has no frozen response for %d", path, w.Code)
	}
	if response.Ref != "" {
		var exists bool
		response, exists = spec.Components.Responses[strings.TrimPrefix(response.Ref, "#/components/responses/")]
		if !exists {
			t.Fatal("unresolved response reference")
		}
	}
	schema := response.Content["application/json"].Schema
	// Existing generic Error401/403/500 references specify no body schema;
	// the actual middleware/application body still conforms to Error.
	if schema.Type == "" && schema.Ref == "" {
		schema = spec.Components.Schemas["Error"]
	}
	value := deviceBody(t, w, w.Code)
	if err := deviceWireValidate(spec, schema, value); err != nil {
		t.Fatal("serialized response violates frozen schema", path, err)
	}
	mediaType, _, err := mime.ParseMediaType(w.Header().Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		t.Fatal("response is not JSON")
	}
	if path == deviceAuthorizationPath || path == deviceTokenPath {
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
			t.Fatal("RFC 6749 §5.1 cache prevention missing")
		}
	}
}

func TestDeviceWireContractCheckCanFail(t *testing.T) {
	spec := deviceSpec(t)
	for _, value := range []any{
		map[string]any{},
		map[string]any{"access_token": "fixture", "token_type": "wrong", "nodeId": "id"},
		map[string]any{"access_token": "fixture", "token_type": "Bearer", "nodeId": "id", "token": "legacy"},
	} {
		if deviceWireValidate(spec, spec.Components.Schemas["DeviceTokenResponse"], value) == nil {
			t.Fatal("contract check accepted incompatible token response")
		}
	}
}

func TestDeviceWireLookupAssociatedUserCheckCanFail(t *testing.T) {
	spec := deviceSpec(t)
	lookup := func(user any) map[string]any {
		return map[string]any{"grantId": "g", "userCode": "ABCD-EFGH", "name": "n", "platform": "linux", "source": "127.0.0.1", "status": "pending", "associatedUser": user}
	}
	schema := spec.Components.Schemas["DeviceGrantLookupResponse"]
	for _, user := range []any{nil, map[string]any{"issuer": "https://idp.example", "subject": "s"}} {
		if err := deviceWireValidate(spec, schema, lookup(user)); err != nil {
			t.Fatalf("valid associatedUser %v rejected: %v", user, err)
		}
	}
	for _, user := range []any{
		map[string]any{},
		map[string]any{"issuer": "", "subject": "s"},
		map[string]any{"issuer": "https://idp.example", "subject": ""},
		"user",
	} {
		if deviceWireValidate(spec, schema, lookup(user)) == nil {
			t.Fatalf("invalid associatedUser %v accepted", user)
		}
	}
}

func TestDeviceProtocolRequestValidation(t *testing.T) {
	for _, path := range []string{deviceAuthorizationPath, deviceTokenPath} {
		base := deviceStartForm()
		if path == deviceTokenPath {
			base = devicePollForm(strings.Repeat("f", 64))
		}
		cases := []struct{ name, key, value, want string }{
			{"missing client", "client_id", "", "invalid_client"}, {"unknown client", "client_id", "other", "invalid_client"},
		}
		if path == deviceAuthorizationPath {
			cases = append(cases, struct{ name, key, value, want string }{"missing name", "name", "", "invalid_request"}, struct{ name, key, value, want string }{"long name", "name", strings.Repeat("a", 121), "invalid_request"}, struct{ name, key, value, want string }{"long UTF8 name", "name", strings.Repeat("界", 41), "invalid_request"}, struct{ name, key, value, want string }{"missing platform", "platform", "", "invalid_request"}, struct{ name, key, value, want string }{"invalid platform", "platform", "plan9", "invalid_request"}, struct{ name, key, value, want string }{"unsupported scope", "scope", "admin", "invalid_scope"})
		} else {
			cases = append(cases, struct{ name, key, value, want string }{"missing grant", "grant_type", "", "invalid_request"}, struct{ name, key, value, want string }{"wrong grant", "grant_type", "authorization_code", "unsupported_grant_type"}, struct{ name, key, value, want string }{"missing code", "device_code", "", "invalid_request"})
		}
		for _, tc := range cases {
			t.Run(path+tc.name, func(t *testing.T) {
				s := deviceServer(t)
				values := url.Values{}
				for key, items := range base {
					values[key] = append([]string(nil), items...)
				}
				values.Set(tc.key, tc.value)
				w := deviceHTTP(s.Handler(), path, "application/x-www-form-urlencoded; charset=UTF-8", values.Encode(), nil, "")
				if deviceBody(t, w, 400)["error"] != tc.want {
					t.Fatal("incorrect request error mapping", tc.name)
				}
				deviceContractResponse(t, path, w)
			})
		}
		for _, tc := range []struct{ name, contentType, body string }{
			{"wrong content type", "application/json", `{}`}, {"missing content type", "", base.Encode()},
			{"wrong charset", "application/x-www-form-urlencoded; charset=iso-8859-1", base.Encode()},
			{"bad escape", "application/x-www-form-urlencoded", base.Encode() + "&extra=%ZZ"},
			{"duplicate", "application/x-www-form-urlencoded", base.Encode() + "&client_id=aegishook"},
			{"duplicate unknown", "application/x-www-form-urlencoded", base.Encode() + "&extra=a&extra=b"},
			{"invalid UTF8", "application/x-www-form-urlencoded", base.Encode() + "&extra=%FF"},
			{"oversized", "application/x-www-form-urlencoded", base.Encode() + "&extra=" + strings.Repeat("x", 2<<20)},
		} {
			t.Run(path+tc.name, func(t *testing.T) {
				s := deviceServer(t)
				w := deviceHTTP(s.Handler(), path, tc.contentType, tc.body, nil, "")
				if deviceBody(t, w, 400)["error"] != "invalid_request" {
					t.Fatal("malformed form accepted")
				}
				deviceContractResponse(t, path, w)
			})
		}
		// Unknown parameters and optional empty scope do not alter the grant.
		s := deviceServer(t)
		values := url.Values{}
		for key, items := range base {
			values[key] = append([]string(nil), items...)
		}
		values.Set("extra", "ignored")
		values.Set("scope", "")
		w := deviceHTTP(s.Handler(), path, "application/x-www-form-urlencoded", values.Encode(), nil, "")
		want := 200
		if path == deviceTokenPath {
			want = 400
		}
		deviceBody(t, w, want)
		deviceContractResponse(t, path, w)
	}
}
