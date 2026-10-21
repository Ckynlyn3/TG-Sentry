package bridge

import (
	"aegishook/internal/core"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
)

// M1 remains a per-hook process. Revalidate on each pre-hook with OPA's
// ETag/If-None-Match protocol under Run's existing deadline; the machine service
// separately owns the 60 s cadence (ARCHITECTURE §2.3 / DECISIONS #7).
func (c client) policyBundle(ctx context.Context, path string) (*core.PolicyBundle, error) {
	if len(c.cfg.BundlePublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("policy verification key missing; re-enroll device")
	}
	bootstrap, err := core.BootstrapPolicyTrust(c.cfg.BundlePublicKey, c.cfg.BundleTrust)
	if err != nil {
		return nil, err
	}
	state, err := core.ReadPolicyTrust(path, bootstrap)
	if err != nil {
		return nil, err
	}
	var cached *core.PolicyBundle
	var etag, signer string
	previous, signer, err := core.ReadPolicyBundleWithTrust(path, state, c.cfg.NodeID)
	if err == nil {
		bundle, _, err := core.VerifyCachedPolicyBundle(previous, signer, state, c.cfg.NodeID)
		if err != nil {
			return nil, err
		}
		cached, etag = &bundle, core.PolicyBundleETag(previous)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	for {
		current, err := bundleTrustRecord(state)
		if err != nil {
			return cached, err
		}
		if !bundleTrustHasKey(current, signer) {
			etag = ""
		}
		response, err := c.fetchPolicyBundle(ctx, etag)
		if err != nil {
			return cached, err
		}
		state, err = c.refreshPolicyTrust(ctx, path, bootstrap, state, response)
		if err != nil {
			return cached, err
		}
		current, err = bundleTrustRecord(state)
		if err != nil {
			return cached, err
		}
		if etag != "" && !bundleTrustHasKey(current, signer) {
			continue // Retirement: force a re-signed 200 before network acceptance.
		}
		if response.notModified {
			return cached, nil
		}
		bundle, err := core.CachePolicyBundleWithTrust(path, response.signed, response.signed.KeyID, bootstrap, c.cfg.NodeID)
		if err != nil {
			return cached, err
		}
		return &bundle, nil
	}
}

type policyBundleResponse struct {
	signed       core.SignedPolicyBundle
	trustVersion int
	notModified  bool
}

func (c client) fetchPolicyBundle(ctx context.Context, etag string) (policyBundleResponse, error) {
	res, err := c.policyGet(ctx, "/bundle", etag)
	if err != nil {
		return policyBundleResponse{}, err
	}
	defer res.Body.Close()
	response := policyBundleResponse{notModified: res.StatusCode == http.StatusNotModified}
	if header := res.Header.Get("TG-Trust-Version"); header != "" {
		response.trustVersion, err = strconv.Atoi(header)
		if err != nil || response.trustVersion < 1 {
			return response, errors.New("invalid policy trust version header")
		}
	}
	if response.notModified {
		if etag == "" || res.Header.Get("ETag") != etag {
			return response, errors.New("policy bundle 304 without matching trusted cache")
		}
		return response, nil
	}
	if res.StatusCode != http.StatusOK {
		return response, fmt.Errorf("policy bundle service returned HTTP %d", res.StatusCode)
	}
	response.signed, err = core.DecodePolicyBundle(res.Body)
	if err != nil {
		return response, errors.New("invalid policy bundle response")
	}
	if validator := res.Header.Get("ETag"); validator != "" && validator != core.PolicyBundleETag(response.signed) {
		return response, errors.New("policy bundle ETag mismatch")
	}
	return response, nil
}

// TUF §5.3 / issue #65 D6: persist each verified successor before asking
// for the next. Core owns all authority, cache-anchor and revision checks.
func (c client) refreshPolicyTrust(ctx context.Context, path string, bootstrap, state core.TrustState, response policyBundleResponse) (core.TrustState, error) {
	current, err := bundleTrustRecord(state)
	if err != nil {
		return state, err
	}
	if response.trustVersion != 0 && response.trustVersion < current.Version {
		return state, errors.New("policy trust version downgrade")
	}
	for {
		current, err := bundleTrustRecord(state)
		if err != nil {
			return state, err
		}
		unknown := response.signed.KeyID != "" && !bundleTrustHasKey(current, response.signed.KeyID)
		if response.trustVersion <= current.Version && !unknown {
			return state, nil
		}
		// Unknown-key catch-up can continue past the advertised target; guard
		// against overflowing the next-version URL.
		if current.Version == int(^uint(0)>>1) {
			return state, errors.New("policy trust version exhausted")
		}
		next, err := c.fetchPolicyTrust(ctx, current.Version+1)
		if err != nil {
			return state, err
		}
		state, err = core.CachePolicyTrustRecord(path, next, bootstrap, c.cfg.NodeID)
		if err != nil {
			return state, err
		}
	}
}

func (c client) fetchPolicyTrust(ctx context.Context, version int) (core.SignedTrustRecord, error) {
	res, err := c.policyGet(ctx, "/keys/"+strconv.Itoa(version), "")
	if err != nil {
		return core.SignedTrustRecord{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return core.SignedTrustRecord{}, fmt.Errorf("policy trust service returned HTTP %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, core.PolicyBundleMaxBytes+1))
	if err != nil {
		return core.SignedTrustRecord{}, fmt.Errorf("read policy trust response: %w", err)
	}
	if len(data) > core.PolicyBundleMaxBytes {
		return core.SignedTrustRecord{}, errors.New("policy trust response exceeds budget")
	}
	var next core.SignedTrustRecord
	if err := json.Unmarshal(data, &next); err != nil {
		return next, fmt.Errorf("decode policy trust response: %w", err)
	}
	return next, nil
}

func (c client) policyGet(ctx context.Context, suffix, etag string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.Endpoint+"/api/v1/client"+suffix, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("policy bundle service unavailable")
	}
	return res, nil
}

// This only reads an already-validated core state for HTTP routing decisions.
// It is not bootstrap, chain or signature verification.
func bundleTrustRecord(state core.TrustState) (core.TrustRecord, error) {
	var current core.TrustRecord
	err := json.Unmarshal(state.Current.Payload, &current)
	return current, err
}

func bundleTrustHasKey(record core.TrustRecord, keyID string) bool {
	for _, key := range record.Keys {
		if key.KeyID == keyID {
			return true
		}
	}
	return false
}
