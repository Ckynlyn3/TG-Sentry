package server

import (
	"bytes"
	"net/http"
	"testing"
)

func TestProtectionIfMatchEntityTagLists(t *testing.T) {
	h := newProtectionHTTP(t)
	installProtectionRule(t, h.engine)
	for _, tc := range []struct {
		name, value string
		want        int
	}{
		{"opaque obsolete", `"obsolete"`, 412},
		{"empty opaque", `""`, 412},
		{"numeric not current", `"1"`, 412},
		{"numeric spelling differs", `"00"`, 412},
		{"weak current", `W/"0"`, 412},
		{"opaque comma", `"old,revision"`, 412},
		{"opaque backslash", `"old\revision"`, 412},
		{"opaque obs-text", "\"\x80\"", 412},
		{"current last", `"obsolete", "0"`, 200},
		{"current first", `"0", "obsolete"`, 200},
		{"weak before strong", `W/"0", "0"`, 200},
		{"strong before weak", `"0", W/"obsolete"`, 200},
		{"comma in obsolete before current", `"old,revision", "0"`, 200},
		{"optional whitespace", " \t\"obsolete\"\t,\t\"0\" \t", 200},
		{"empty list members", `, , "0", ,`, 200},
		{"wildcard remains unsupported", `*`, 400},
		{"wildcard cannot mix with tags", `"0", *`, 400},
		{"missing base", ``, 428},
		{"unquoted opaque", `obsolete`, 400},
		{"space inside opaque", `"old revision"`, 400},
		{"unterminated", `"obsolete`, 400},
		{"missing comma", `"obsolete" "0"`, 400},
		{"invalid after current", `"0", malformed`, 400},
		{"malformed weak", `W/0`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := *h
			client.t = t
			client.etag = tc.value
			client.call("POST", "/api/v1/templates/review", templateInput("block"), tc.want, "")
		})
	}
}

func TestProtectionIfMatchListAlsoGuardsConfirm(t *testing.T) {
	h := newProtectionHTTP(t)
	installProtectionRule(t, h.engine)
	h.etag = `"obsolete", "0"`
	r := h.call("POST", "/api/v1/templates/review", templateInput("block"), 200, "")
	h.etag = `W/"0", "obsolete", "0"`
	h.call("POST", "/api/v1/templates", map[string]any{"reviewId": r["id"]}, 200, "")
	h.etag = `"obsolete", "0"`
	h.call("POST", "/api/v1/templates", map[string]any{"reviewId": r["id"]}, 412, "")
}

func TestProtectionIfMatchCombinesRepeatedFieldLines(t *testing.T) {
	h := newProtectionHTTP(t)
	installProtectionRule(t, h.engine)
	req, err := http.NewRequest("POST", h.url+"/api/v1/templates/review", bytes.NewBufferString(`{"name":"fixture","rules":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("If-Match", `"obsolete"`)
	req.Header.Add("If-Match", `"0"`)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("repeated If-Match fields rejected: %d", resp.StatusCode)
	}
}
