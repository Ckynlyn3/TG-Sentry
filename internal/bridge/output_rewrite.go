package bridge

import (
	"aegishook/internal/core"
	"aegishook/internal/localaddr"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RunToolOutput is a separate logical operation, never a native permission
// decision or /result acknowledgement. Review identity is supplied outside the
// frozen two-field payload. S3 adapters own leaf-only withholding on failure.
func RunToolOutput(connection, reviewID string, in io.Reader, out, stderr io.Writer) int {
	fail := func() int { fmt.Fprintln(stderr, "Tool output transformation unavailable"); return 1 }
	id, err := hex.DecodeString(reviewID)
	if err != nil || len(id) != 32 {
		return fail()
	} // Existing SHA-256 review identity.
	data, err := core.ReadToolOutputJSON(in)
	if err != nil {
		return fail()
	}
	request, err := core.DecodeToolOutputRequest(data)
	if err != nil {
		return fail()
	}
	b, err := readConnection(connection)
	var cfg Config
	if err != nil || json.Unmarshal(b, &cfg) != nil {
		return fail()
	}
	endpoint, err := localaddr.Endpoint(cfg.Endpoint)
	if err != nil || cfg.Token == "" {
		return fail()
	}
	cfg.Endpoint = endpoint
	// Reuse bridge.go's existing HTTP budget; BTPII's whole-leaf budget is lower.
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	c := client{cfg: cfg, http: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") }}}
	var response core.ToolOutputResponse
	if c.request(ctx, "/reviews/"+reviewID+"/transform-tool-output", request, &response) != nil {
		return fail()
	}
	if json.NewEncoder(out).Encode(response) != nil {
		return fail()
	}
	return 0
}
