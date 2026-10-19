package core

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

type ClientNode struct {
	Tags      []string  `json:"tags,omitempty"`
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Platform  string    `json:"platform"`
	CreatedAt time.Time `json:"createdAt"`
	Revoked   bool      `json:"revoked"`
}

// The stored form keeps credential hashes out of all management responses.
type storedClientNode struct {
	ClientNode
	Hash string `json:"tokenHash"`
}

// EnrollmentOptions extends the existing one-off flow. An omitted expiry keeps
// AegisHook's ten-minute default; reusable maxUses=0 means unlimited (NetBird).
type EnrollmentOptions struct {
	Type      string     `json:"type"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	MaxUses   int        `json:"maxUses"`
}

type Enrollment struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	ExpiresAt time.Time `json:"expiresAt"`
	MaxUses   int       `json:"maxUses"`
	UsedTimes int       `json:"usedTimes"`
	Revoked   bool      `json:"revoked"`
}

type enrollment struct {
	Enrollment
	Used bool `json:"used"` // Retained for old binaries and pre-#6 one-off keys.
}
type EnrollmentCode struct {
	Enrollment
	Code string `json:"code"`
}
type ClientConnection struct {
	Endpoint        string             `json:"endpoint"`
	Token           string             `json:"token"`
	NodeID          string             `json:"nodeId"`
	BundlePublicKey []byte             `json:"bundlePublicKey,omitempty"`
	BundleTrust     *SignedTrustRecord `json:"bundleTrust,omitempty"`
}

func credentialHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func (e *Engine) CreateEnrollment(ctx context.Context, name string, options ...EnrollmentOptions) (EnrollmentCode, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(name) > 120 || len(options) > 1 {
		return EnrollmentCode{}, errors.New("invalid setup key options")
	}
	opts := EnrollmentOptions{Type: "one-off"}
	if len(options) == 1 {
		opts = options[0]
	}
	if opts.Type == "" {
		opts.Type = "one-off"
	}
	if !hasExact(opts.Type, "one-off", "reusable") || opts.MaxUses < 0 || (opts.Type == "one-off" && opts.MaxUses > 1) {
		return EnrollmentCode{}, errors.New("invalid setup key type or usage limit")
	}
	if opts.Type == "one-off" {
		opts.MaxUses = 1
	}
	expires := e.clock().Add(10 * time.Minute) // Existing AegisHook enrollment default.
	if opts.ExpiresAt != nil {
		expires = *opts.ExpiresAt
	}
	if !e.clock().Before(expires) {
		return EnrollmentCode{}, errors.New("setup key expiry must be in the future")
	}
	code := ID() + ID() // Two existing 128-bit crypto/rand IDs: 256 random bits.
	record := enrollment{Enrollment: Enrollment{ID: credentialHash(code), Name: name, Type: opts.Type, ExpiresAt: expires, MaxUses: opts.MaxUses}}
	if err := e.change(ctx, "client_enrollments", record.ID, record, "client.enrollment.create", "Setup key created"); err != nil {
		return EnrollmentCode{}, errors.New("cannot create setup key")
	}
	return EnrollmentCode{Enrollment: record.Enrollment, Code: code}, nil
}

// Legacy records omitted type/maxUses/usedTimes; never resurrect consumed keys.
func (r enrollment) normalized() enrollment {
	if r.Type == "" {
		r.Type = "one-off"
		r.MaxUses = 1
		if r.Used {
			r.UsedTimes = 1
		}
	}
	return r
}

func (e *Engine) Enrollments() ([]Enrollment, error) {
	records, err := list[enrollment](e, "client_enrollments")
	out := []Enrollment{}
	for _, record := range records {
		out = append(out, record.normalized().Enrollment)
	}
	return out, err
}

func (e *Engine) RevokeEnrollment(ctx context.Context, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var record enrollment
	if e.get("client_enrollments", id, &record) != nil {
		return errors.New("setup key not found")
	}
	record = record.normalized() // Persist legacy usage before used carries revocation.
	record.Revoked = true
	record.Used = true // Pre-#6 binaries only check used; preserve revocation on downgrade.
	return e.change(ctx, "client_enrollments", id, record, "client.enrollment.revoke", "Setup key revoked")
}
func (e *Engine) EnrollClient(code, platform string) (ClientConnection, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(code) != 64 || !hasExact(platform, "linux", "darwin", "windows") {
		return ClientConnection{}, errors.New("接入码或平台无效")
	}
	var record enrollment
	hash := credentialHash(code)
	if e.get("client_enrollments", hash, &record) != nil || subtle.ConstantTimeCompare([]byte(hash), []byte(record.ID)) != 1 {
		return ClientConnection{}, errors.New("invalid or unavailable setup key")
	}
	record = record.normalized()
	if record.Revoked || record.Used || !e.clock().Before(record.ExpiresAt) || (record.MaxUses > 0 && record.UsedTimes >= record.MaxUses) {
		return ClientConnection{}, errors.New("invalid or unavailable setup key")
	}
	record.UsedTimes++
	record.Used = record.MaxUses > 0 && record.UsedTimes >= record.MaxUses
	return e.issueClientCredential("client_enrollments", record.ID, record, record.Name, platform)
}

// Called with e.mu held. Consumption, credential issuance and audit commit together.
func (e *Engine) issueClientCredential(kind, id string, record any, name, platform string) (ClientConnection, error) {
	token := ID() + ID()
	node := storedClientNode{ClientNode: ClientNode{ID: ID(), Name: name, Platform: platform, CreatedAt: e.clock()}, Hash: credentialHash(token)}
	tx, err := e.beginTenant()
	if err != nil {
		return ClientConnection{}, err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(insertRecord, eventTenant(), "client_nodes", node.ID, string(mustJSON(node))); err != nil {
		return ClientConnection{}, err
	}
	if _, err = tx.Exec("UPDATE records SET payload=$1 WHERE tenant_id=$2 AND kind=$3 AND id=$4", string(mustJSON(record)), eventTenant(), kind, id); err != nil {
		return ClientConnection{}, err
	}
	audit := Audit{Actor: SystemActor("device"), ID: ID(), Action: "client.enroll", Subject: node.ID, Detail: "设备已接入", CreatedAt: e.clock()}
	if _, err = tx.Exec(insertRecord, eventTenant(), "audit", audit.ID, string(mustJSON(audit))); err != nil {
		return ClientConnection{}, err
	}
	if err = tx.Commit(); err != nil {
		return ClientConnection{}, err
	}
	if e.Notify != nil {
		e.Notify()
	}
	trust := cloneSignedTrustRecord(e.bundleManifest.Records[len(e.bundleManifest.Records)-1])
	return ClientConnection{Token: token, NodeID: node.ID, BundleTrust: &trust, BundlePublicKey: append([]byte(nil), e.bundleKey.Public().(ed25519.PublicKey)...)}, nil
}
func (e *Engine) AuthenticateClient(token string) (ClientNode, bool) {
	if len(token) != 64 {
		return ClientNode{}, false
	}
	hash := credentialHash(token)
	tx, err := e.beginTenant()
	if err != nil {
		return ClientNode{}, false
	}
	defer tx.Rollback()
	var payload []byte
	if err := tx.QueryRow("SELECT payload FROM records WHERE tenant_id=$1 AND kind='client_nodes' AND "+e.jsonField("", "tokenHash")+"=$2", eventTenant(), hash).Scan(&payload); err != nil {
		return ClientNode{}, false
	}
	var node storedClientNode
	if json.Unmarshal(payload, &node) != nil || node.Revoked || subtle.ConstantTimeCompare([]byte(hash), []byte(node.Hash)) != 1 {
		return ClientNode{}, false
	}
	return node.ClientNode, true
}
func (e *Engine) ClientNodes() ([]ClientNode, error) {
	nodes, err := list[storedClientNode](e, "client_nodes")
	if err != nil {
		return nil, err
	}
	state, err := e.Protection()
	if err != nil {
		return nil, err
	}
	out := []ClientNode{}
	for _, node := range nodes {
		node.Tags = append([]string{}, state.Tags[node.ID]...)
		out = append(out, node.ClientNode)
	}
	return out, err
}
func (e *Engine) RevokeClient(ctx context.Context, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var node storedClientNode
	if err := e.get("client_nodes", id, &node); err != nil {
		return errors.New("设备不存在")
	}
	node.Revoked = true
	return e.change(ctx, "client_nodes", id, node, "client.revoke", "撤销设备接入")
}
func (e *Engine) ClientOwnsInstance(nodeID, instanceID string) bool {
	var i Instance
	return e.get("instances", screenedIdentifier(instanceID), &i) == nil && i.NodeID == nodeID
}
