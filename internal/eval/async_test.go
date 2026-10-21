package eval

import (
	"aegishook/internal/core"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFullPathWaitsForRealAsyncStoredModelOutcome(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "terminal", true: "E_MODEL"}[fail], func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				<-release
				if fail {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"choices":[{"message":{"content":"{\"decision\":\"approve\",\"comment\":\"实际操作：处理合成测试；成功后的后果：返回测试结果；命中规则：D1\"}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
			}))
			defer server.Close()
			c := testConfig()
			c.Settings.Mode = "model"
			c.Settings.Model = core.ModelConfig{ProcessingClass: core.ModelProcessingSelfHosted, Protocol: "openai", BaseURL: server.URL, Model: "synthetic-self-hosted", Tested: true}
			e, cleanup, err := OpenIsolated(c, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			done := make(chan PathResult, 1)
			errs := make(chan error, 1)
			go func() {
				got, err := FullPath(context.Background(), e, Item{ID: "fake-model", Review: &core.ReviewInput{ToolName: "FAKE_TOOL", Arguments: map[string]any{"fake": "synthetic"}}}, time.Millisecond)
				done <- got
				errs <- err
			}()
			<-entered
			select {
			case <-done:
				t.Fatal("Submit response was mistaken for terminal outcome")
			default:
			}
			close(release)
			got := <-done
			if err = <-errs; err != nil || got.ReviewPath != "model" || got.Decision == "pending" || got.LatencyMS <= 0 {
				t.Fatal(got, err)
			}
			if fail && got.UnavailableReason != "E_MODEL" {
				t.Fatal(got)
			}
			if !fail && (got.Decision != "approve" || got.UnavailableReason != "") {
				t.Fatal(got)
			}
			stored, err := e.Reviews()
			if err != nil || len(stored) != 1 || stored[0].ReviewPath != "model" || stored[0].Decision != got.Decision {
				t.Fatal("terminal result not stored", err)
			}
		})
	}
}
