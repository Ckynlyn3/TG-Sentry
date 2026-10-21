package core

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
)

var ErrDeviceGrantPrecondition = errors.New("device grant changed; review again")

func deviceGrantLookup(g storedDeviceGrant) DeviceGrantLookup {
	var user *AssociatedUser
	if g.AssociatedUser != nil {
		copy := *g.AssociatedUser
		user = &copy
	}
	return DeviceGrantLookup{GrantID: g.ID, UserCode: displayUserCode(g.UserCode), Name: g.Name, Platform: g.Platform, Source: g.Source, Status: g.Status, AssociatedUser: user}
}

// Strong content validator, reusing PolicyBundleETag's SHA-256 convention.
// Only reviewed metadata is hashed, not private poll timing (RFC 9110 §8.8.3
// https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3).
func DeviceGrantETag(g DeviceGrantLookup) string {
	sum := sha256.Sum256(mustJSON(g))
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// Called under e.mu; shared expiry/terminal checks for preview and confirmation.
func (e *Engine) pendingDeviceAssociation(id string) (storedDeviceGrant, error) {
	var g storedDeviceGrant
	if err := e.get("device_grants", id, &g); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return g, ErrDeviceGrantNotFound
		}
		return g, err
	}
	if !e.clock().Before(g.ExpiresAt) {
		return g, ErrDeviceGrantNotFound
	}
	if g.Status != deviceStatusPending || g.AssociatedUser != nil {
		return g, ErrDeviceGrantDecided
	}
	return g, nil
}

func (e *Engine) DeviceGrantAssociation(id string) (DeviceGrantLookup, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	g, err := e.pendingDeviceAssociation(id)
	if err != nil {
		return DeviceGrantLookup{}, err
	}
	return deviceGrantLookup(g), nil
}

// Caller supplies only the identity from the existing verified OIDC callback;
// the transport rejects identity/grant selection fields. Confirmation changes no
// decision and issues nothing (#72 S1; RFC 8628 §3.3).
func (e *Engine) ConfirmDeviceGrantAssociation(ctx context.Context, id string, user AssociatedUser) (DeviceGrantLookup, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if user.Issuer == "" || user.Subject == "" {
		return DeviceGrantLookup{}, errors.New("verified principal required")
	}
	g, err := e.pendingDeviceAssociation(id)
	if err != nil {
		return DeviceGrantLookup{}, err
	}
	g.AssociatedUser = &user
	if err := e.change(ctx, "device_grants", g.ID, g, "client.device.associate", "Device account association confirmed"); err != nil {
		return DeviceGrantLookup{}, err
	}
	return deviceGrantLookup(g), nil
}
