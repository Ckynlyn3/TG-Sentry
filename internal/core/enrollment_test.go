package core

import (
	"aegishook/internal/teststore"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSetupKeyLimitsExpiryAndRevocation(t *testing.T) {
	e := engine(t)
	now := time.Now().UTC()
	e.clock = func() time.Time { return now }
	expires := now.Add(time.Minute)
	key, err := e.CreateEnrollment(testActorContext(), "fleet", EnrollmentOptions{Type: "reusable", ExpiresAt: &expires, MaxUses: 2})
	if err != nil {
		t.Fatal(err)
	}
	first, err := e.EnrollClient(key.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.EnrollClient(key.Code, "windows")
	if err != nil {
		t.Fatal(err)
	}
	if first.Token == second.Token || first.NodeID == second.NodeID {
		t.Fatal("devices share a credential")
	}
	if _, err := e.EnrollClient(key.Code, "darwin"); err == nil {
		t.Fatal("usage limit ignored")
	}
	if _, ok := e.AuthenticateClient(key.Code); ok {
		t.Fatal("setup key authenticated as a device")
	}
	if err := e.RevokeClient(testActorContext(), first.NodeID); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.AuthenticateClient(first.Token); ok {
		t.Fatal("revoked credential accepted on next call")
	}
	if _, ok := e.AuthenticateClient(second.Token); !ok {
		t.Fatal("revoking one device revoked another")
	}
	key, err = e.CreateEnrollment(testActorContext(), "expires", EnrollmentOptions{Type: "reusable", ExpiresAt: &expires})
	if err != nil {
		t.Fatal(err)
	}
	now = expires
	if _, err := e.EnrollClient(key.Code, "linux"); err == nil {
		t.Fatal("key accepted at expiry")
	}
	now = now.Add(time.Second)
	if _, err := e.EnrollClient(key.Code, "linux"); err == nil {
		t.Fatal("key accepted past expiry")
	}
	key, err = e.CreateEnrollment(testActorContext(), "revoked", EnrollmentOptions{Type: "reusable"})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := e.EnrollClient(key.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.RevokeEnrollment(testActorContext(), key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.EnrollClient(key.Code, "linux"); err == nil {
		t.Fatal("revoked setup key accepted")
	}
	if _, ok := e.AuthenticateClient(connection.Token); !ok {
		t.Fatal("setup key revoke invalidated enrolled device")
	}
	keys, err := e.Enrollments()
	if err != nil || len(keys) != 3 {
		t.Fatal("key metadata unavailable", err)
	}
	for _, k := range keys {
		if k.ID == key.ID && !k.Revoked {
			t.Fatal("revocation absent from metadata")
		}
	}
}

func TestSetupKeyValidationAndLegacy(t *testing.T) {
	e := engine(t)
	past := time.Now().Add(-time.Minute)
	for _, options := range []EnrollmentOptions{
		{Type: "unknown"}, {MaxUses: -1}, {Type: "one-off", MaxUses: 2}, {ExpiresAt: &past},
	} {
		if _, err := e.CreateEnrollment(testActorContext(), "invalid", options); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
	if _, err := e.CreateEnrollment(testActorContext(), strings.Repeat("a", 121)); err == nil {
		t.Fatal("long name accepted")
	}
	for _, code := range []string{"", strings.Repeat("0", 64)} {
		if _, err := e.EnrollClient(code, "linux"); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
	key, err := e.CreateEnrollment(testActorContext(), "legacy-default")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.EnrollClient(key.Code, "invalid"); err == nil {
		t.Fatal("invalid platform accepted")
	}
	if _, err := e.EnrollClient(key.Code, "linux"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.EnrollClient(key.Code, "linux"); err == nil {
		t.Fatal("default no longer one-off")
	}
	// Pre-#6 records had only id/name/expiresAt/used. Keep unconsumed keys valid,
	// and never reset an already-consumed legacy key's usage.
	for _, used := range []bool{false, true} {
		code := ID() + ID()
		legacy := map[string]any{"id": credentialHash(code), "name": "legacy", "expiresAt": time.Now().Add(time.Minute), "used": used}
		if err := e.put("client_enrollments", credentialHash(code), legacy); err != nil {
			t.Fatal(err)
		}
		_, err := e.EnrollClient(code, "linux")
		if (err == nil) == used {
			t.Fatal("legacy key usage changed")
		}
	}
	if err := e.RevokeEnrollment(testActorContext(), "missing"); err == nil {
		t.Fatal("nonexistent key revoked")
	}
}

func TestSetupKeyConcurrentLimitAndAtomicAudit(t *testing.T) {
	e := engine(t)
	key, err := e.CreateEnrollment(testActorContext(), "one slot", EnrollmentOptions{Type: "reusable", MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	connections := make(chan ClientConnection, 8) // Existing enrollment concurrency fixture width.
	for i := 0; i < cap(connections); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := e.EnrollClient(key.Code, "linux")
			if err == nil {
				connections <- c
			}
		}()
	}
	wg.Wait()
	close(connections)
	if len(connections) != 1 {
		t.Fatal("usage limit not atomic")
	}
	key, err = e.CreateEnrollment(testActorContext(), "rollback")
	if err != nil {
		t.Fatal(err)
	}
	rejectAudit(t, e)
	if _, err := e.EnrollClient(key.Code, "linux"); err == nil {
		t.Fatal("audit failure accepted")
	}
	keys, err := e.Enrollments()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.ID == key.ID && k.UsedTimes != 0 {
			t.Fatal("failed issuance consumed a use")
		}
	}
	nodes, err := e.ClientNodes()
	if err != nil || len(nodes) != 1 {
		t.Fatal("failed issuance created a device", err)
	}
}

func TestSetupKeyPersistenceAndTenantIsolation(t *testing.T) {
	dir := teststore.Dir(t, t.TempDir())
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	key, err := e.CreateEnrollment(testActorContext(), "persistent", EnrollmentOptions{Type: "reusable", MaxUses: 2})
	if err != nil {
		e.Close()
		t.Fatal(err)
	}
	connection, err := e.EnrollClient(key.Code, "linux")
	if err != nil {
		e.Close()
		t.Fatal(err)
	}
	if err := e.RevokeClient(testActorContext(), connection.NodeID); err != nil {
		e.Close()
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, ok := e.AuthenticateClient(connection.Token); ok {
		t.Fatal("revocation lost on reopen")
	}
	if _, err := e.EnrollClient(key.Code, "darwin"); err != nil {
		t.Fatal("reusable key lost on reopen", err)
	}
	if _, err := e.EnrollClient(key.Code, "linux"); err == nil {
		t.Fatal("usage count lost on reopen")
	}
	foreignCode := ID() + ID()
	payload, _ := json.Marshal(map[string]any{"id": credentialHash(foreignCode), "name": "foreign", "expiresAt": time.Now().Add(time.Minute)})
	if _, err := teststore.Admin(t, e.DB).Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES('other','client_enrollments',$1,$2)", credentialHash(foreignCode), string(payload)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.EnrollClient(foreignCode, "linux"); err == nil {
		t.Fatal("foreign setup key accepted")
	}
	if err := e.RevokeEnrollment(testActorContext(), credentialHash(foreignCode)); err == nil {
		t.Fatal("foreign setup key revoked")
	}
	keys, err := e.Enrollments()
	if err != nil || len(keys) != 1 {
		t.Fatal("foreign setup key listed", err)
	}
	rows, err := teststore.Admin(t, e.DB).Query("SELECT payload FROM records WHERE tenant_id='default' AND kind IN ('client_enrollments','client_nodes','audit')")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(payload, key.Code) || strings.Contains(payload, connection.Token) {
			t.Fatal("plaintext secret persisted")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestSetupKeyRevocationSurvivesLegacyRollback(t *testing.T) {
	e := engine(t)
	for _, keyType := range []string{"one-off", "reusable"} {
		t.Run(keyType, func(t *testing.T) {
			key, err := e.CreateEnrollment(testActorContext(), "rollback", EnrollmentOptions{Type: keyType})
			if err != nil {
				t.Fatal(err)
			}
			if err := e.RevokeEnrollment(testActorContext(), key.ID); err != nil {
				t.Fatal(err)
			}
			// Exact pre-#6 enrollment fields and acceptance guard. A downgraded
			// binary ignores revoked/type/maxUses, so used must carry revocation.
			var legacy struct {
				ID        string    `json:"id"`
				Name      string    `json:"name"`
				ExpiresAt time.Time `json:"expiresAt"`
				Used      bool      `json:"used"`
			}
			if e.get("client_enrollments", credentialHash(key.Code), &legacy) == nil && !legacy.Used && e.clock().Before(legacy.ExpiresAt) {
				t.Fatal("pre-#6 enrollment guard accepts revoked key")
			}
			if !legacy.Used {
				t.Fatal("revocation missing legacy used flag")
			}
		})
	}
}

func TestRevokingUnusedLegacyKeyKeepsUsageCount(t *testing.T) {
	e := engine(t)
	code := ID() + ID()
	id := credentialHash(code)
	legacy := map[string]any{"id": id, "name": "legacy", "expiresAt": time.Now().Add(time.Minute), "used": false}
	if err := e.put("client_enrollments", id, legacy); err != nil {
		t.Fatal(err)
	}
	if err := e.RevokeEnrollment(testActorContext(), id); err != nil {
		t.Fatal(err)
	}
	keys, err := e.Enrollments()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if key.ID == id && (!key.Revoked || key.UsedTimes != 0) {
			t.Fatalf("revoked unused legacy key reported revoked=%v usedTimes=%d", key.Revoked, key.UsedTimes)
		}
	}
}
