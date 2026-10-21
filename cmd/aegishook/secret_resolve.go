package main

import (
	"aegishook/internal/core"
	"aegishook/internal/localaddr"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// OpenClaw exec-provider contract (protocol v1, JSON-only stdout, 1 MiB
// output and 5000 ms default deadline):
// https://docs.openclaw.ai/gateway/secrets/secretref-contract
const secretResolveLimit = core.SecretResolveLimit

// #45 frozen plan §§2–3 requires a deadline below the provider's 5000 ms.
// Reuse prompt_attack.go's existing 4500 ms hook budget, not a new timeout.
var secretResolveTimeout = core.ReviewHookBudget

var secretResolveID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$`)
var errSecretResolve = errors.New("secret resolution failed")

func runSecretResolve(args []string, input io.Reader, output io.Writer) error {
	return runSecretResolveBefore(args, input, output, time.Now().Add(secretResolveTimeout))
}
func runSecretResolveBefore(args []string, input io.Reader, output io.Writer, deadline time.Time) error {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	// Cover stdin/config reads as well as all HTTP requests. Buffer output so a
	// timed-out worker cannot emit a late plaintext response before process exit.
	var result bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- runSecretResolveContext(ctx, args, input, &result) }()
	select {
	case <-ctx.Done():
		return errSecretResolve
	case err := <-done:
		if err != nil || ctx.Err() != nil {
			return errSecretResolve
		}
		if _, err := output.Write(result.Bytes()); err != nil {
			return errSecretResolve
		}
		return nil
	}
}
func runSecretResolveContext(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	f := flag.NewFlagSet("secret-resolve", flag.ContinueOnError)
	f.SetOutput(io.Discard) // Neither flag values nor secrets reach stdout/stderr.
	home, _ := os.UserHomeDir()
	var connection, agent string
	f.StringVar(&connection, "connection", filepath.Join(home, ".aegishook-client", "adapter", "connection.json"), "saved device connection")
	f.StringVar(&agent, "agent", "", "explicit agent binding label")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || agent == "" {
		return errSecretResolve
	}
	// Named local exception: bound stdin to the provider's documented output
	// ceiling as well; the upstream contract defines no stdin size ceiling.
	data, err := io.ReadAll(io.LimitReader(input, secretResolveLimit+1))
	if err != nil || len(data) > secretResolveLimit {
		return errSecretResolve
	}
	var request struct {
		ProtocolVersion int      `json:"protocolVersion"`
		Provider        string   `json:"provider"`
		IDs             []string `json:"ids"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.ProtocolVersion != 1 || request.Provider == "" || len(request.IDs) == 0 {
		return errSecretResolve
	}
	for _, id := range request.IDs {
		if !secretResolveID.MatchString(id) {
			return errSecretResolve
		}
		for _, segment := range strings.Split(id, "/") {
			if segment == "." || segment == ".." {
				return errSecretResolve
			}
		}
	}
	data, err = os.ReadFile(connection)
	if err != nil {
		return errSecretResolve
	}
	var conn core.ClientConnection
	if json.Unmarshal(data, &conn) != nil || conn.Token == "" || conn.NodeID == "" {
		return errSecretResolve
	}
	endpoint, err := localaddr.Endpoint(conn.Endpoint)
	if err != nil {
		return errSecretResolve
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return errSecretResolve }}
	values := make(map[string]string, len(request.IDs))
	totalBytes := 0
	for _, id := range request.IDs {
		if _, exists := values[id]; exists {
			continue
		}
		value, err := resolveCredentialHTTP(ctx, client, endpoint, conn.Token, agent, id)
		if err != nil {
			return errSecretResolve
		}
		totalBytes += len(value) + len(id)
		if totalBytes > secretResolveLimit {
			return errSecretResolve
		}
		values[id] = value
	}
	result, err := json.Marshal(struct {
		ProtocolVersion int               `json:"protocolVersion"`
		Values          map[string]string `json:"values"`
	}{1, values})
	if err != nil || len(result)+1 > secretResolveLimit {
		return errSecretResolve
	}
	if _, err := output.Write(append(result, '\n')); err != nil {
		return errSecretResolve
	}
	return nil
}
func resolveCredentialHTTP(ctx context.Context, client *http.Client, endpoint, token, agent, id string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint+"/api/v1/client/credentials/"+url.PathEscape(id)+"?agent="+url.QueryEscape(agent), nil)
	if err != nil {
		return "", errSecretResolve
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return "", errSecretResolve
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", errSecretResolve
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, secretResolveLimit+1))
	if err != nil || len(data) > secretResolveLimit {
		return "", errSecretResolve
	}
	var value core.ResolvedCredential
	if json.Unmarshal(data, &value) != nil || value.ID != id || value.Value == "" {
		return "", errSecretResolve
	}
	return value.Value, nil
}
