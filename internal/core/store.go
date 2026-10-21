package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	IntegrationBinary string
	lock              *os.File
	DB                *sql.DB
	postgres          bool
	Dir               string
	mu                sync.Mutex
	Settings          Settings
	Notify            func()
	stop              chan struct{}
	workers           sync.WaitGroup
	closeOnce         sync.Once
	closeErr          error
	deliveryCancel    context.CancelFunc
	deliveryWake      chan struct{}
	syslog            *syslogConfig
	kafka             *kafkaConfig
	kafkaWake         chan struct{}
	clock             func() time.Time
	bundleKey         ed25519.PrivateKey
	credentialsKey    []byte
	bundleManifest    bundleManifest
	paNSFA            *NSFAClient
}

func ID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func Open(dir string) (*Engine, error) {
	syslog, err := loadSyslogConfig(os.Getenv)
	if err != nil {
		return nil, err
	}
	kafka, err := loadKafkaConfig(os.Getenv)
	if err != nil {
		return nil, err
	}
	var kafkaSender *kafkaSender
	if kafka != nil {
		kafkaSender, err = newKafkaSender(kafka)
		if err != nil {
			return nil, err
		}
	}
	opened := false
	defer func() {
		if !opened && kafkaSender != nil {
			kafkaSender.client.Close()
		}
	}()
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "process.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockProcessFile(lock); err != nil {
		lock.Close()
		return nil, errors.New("该数据目录已有 AegisHook 进程，请使用运行中服务的界面或命令")
	}
	defer func() {
		if !opened {
			lock.Close()
		}
	}()
	db, postgres, err := openDatabase(dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !opened {
			db.Close()
		}
	}()
	e := &Engine{DB: db, postgres: postgres, lock: lock, Dir: dir, stop: make(chan struct{}), clock: time.Now, syslog: syslog, kafka: kafka, deliveryWake: make(chan struct{}, 1), kafkaWake: make(chan struct{}, 1)}
	if err = e.loadBundleKey(); err != nil {
		return nil, err
	}
	if err = e.loadCredentialKey(false); err != nil {
		return nil, err
	}
	e.Settings = Settings{Mode: "human", Model: ModelConfig{Protocol: "openai"}, Prompt: DefaultPrompt, Version: 1, ApprovalSeconds: 600, ModelSeconds: 20}
	if err = e.get("settings", "current", &e.Settings); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if e.Settings.Model.Protocol == "" {
		e.Settings.Model.Protocol = "openai"
	}
	key, err := os.ReadFile(filepath.Join(dir, "model.key"))
	if err == nil {
		e.Settings.Model.APIKey = string(key)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	e.Settings.Model.HasKey = e.Settings.Model.APIKey != ""
	if err = e.upgradePrompt(); err != nil {
		return nil, err
	}
	if err = e.put("settings", "current", e.Settings); err != nil {
		return nil, err
	}
	rules, err := e.Rules()
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		for _, r := range BuiltinRules() {
			if err = e.put("rules", r.ID, r); err != nil {
				return nil, err
			}
		}
	} else if err = e.upgradeBuiltinRules(rules); err != nil {
		return nil, err
	}
	reviews, err := e.Reviews()
	if err != nil {
		return nil, err
	}
	for _, r := range reviews {
		if r.Decision == "pending" {
			r.Decision = "reject"
			r.NeedsHuman = false
			r.RuleID = "E_RESTART"
			r.Comment = "审查服务已重启，原请求已失效，请重新提交。"
			r.Execution = "not_executed"
			now := e.clock()
			r.DecidedAt = &now
			if err = e.commitReview(WithActor(context.Background(), SystemActor("startup")), r, "review.restart"); err != nil {
				return nil, err
			}
		}
	}
	instances, err := e.Instances()
	if err != nil {
		return nil, err
	}
	for _, i := range instances {
		if i.State != "disconnected" {
			i.DisconnectReason = "service_restart"
		}
		i.State = "disconnected"
		i.Online = false
		if err = e.put("instances", i.ID, i); err != nil {
			return nil, err
		}
	}
	opened = true
	e.workers.Add(1)
	go e.sweepLoop()
	if syslog != nil || kafka != nil {
		ctx, cancel := context.WithCancel(context.Background())
		e.deliveryCancel = cancel
		if syslog != nil {
			e.workers.Add(1)
			go e.logDeliveryLoop(ctx)
		}
		if kafkaSender != nil {
			e.workers.Add(1)
			go e.kafkaDeliveryLoop(ctx, kafkaSender)
		}
	}
	return e, nil
}
func (e *Engine) Close() error {
	e.closeOnce.Do(func() {
		close(e.stop)
		if e.deliveryCancel != nil {
			e.deliveryCancel()
		}
		e.workers.Wait() // Join store-owning workers before closing the single connection.
		e.closeErr = errors.Join(e.DB.Close(), e.lock.Close())
	})
	return e.closeErr
}

// Clock exposes the engine's single time source so the serve path's periodic
// workers read the same clock the store writes with. Read-only; tests may
// replace the source in-package.
func (e *Engine) Clock() time.Time { return e.clock() }
func (e *Engine) get(kind, id string, out any) error {
	tx, err := e.beginTenant()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var b []byte
	err = tx.QueryRow("SELECT payload FROM records WHERE tenant_id=$1 AND kind=$2 AND id=$3", eventTenant(), kind, id).Scan(&b)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}
func (e *Engine) put(kind, id string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tx, err := e.beginTenant()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(upsertRecord, eventTenant(), kind, id, string(b)); err != nil {
		return err
	}
	return tx.Commit()
}
func list[T any](e *Engine, kind string) ([]T, error) {
	tx, err := e.beginTenant()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query("SELECT payload FROM records WHERE tenant_id=$1 AND kind=$2 ORDER BY "+e.jsonField("", "createdAt")+" DESC NULLS LAST,id", eventTenant(), kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		var b []byte
		var v T
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (e *Engine) change(ctx context.Context, kind, id string, v any, action, detail string) error {
	if r, ok := v.(Review); kind == "reviews" && ok {
		v = suppressedReview(r) // Before any payload serialization or insertion.
		if r.LogSuppression != nil {
			detail = ""
			if action == "review.human" {
				detail = r.Decision
			}
		}
	}
	omitAudit := false
	if i, ok := v.(Instance); kind == "instances" && ok && hasExact(action, "instance.register", "instance.disconnect") {
		// Admission provenance captured at registration, not current config.
		omitAudit = i.LogSuppression != nil
	}
	tx, err := e.beginTenant()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if v == nil {
		_, err = tx.Exec("DELETE FROM records WHERE tenant_id=$1 AND kind=$2 AND id=$3", eventTenant(), kind, id)
	} else {
		var b []byte
		b, err = json.Marshal(v)
		if err == nil {
			_, err = tx.Exec(upsertRecord, eventTenant(), kind, id, string(b))
		}
	}
	if err != nil {
		return err
	}
	var next *Settings
	if kind == "rules" || kind == "scopes" || kind == "protection" {
		s := e.Settings
		s.Version++
		next = &s
		b, marshalErr := json.Marshal(s)
		if marshalErr != nil {
			return marshalErr
		}
		if _, err = tx.Exec(upsertRecord, eventTenant(), "settings", "current", string(b)); err != nil {
			return err
		}
	}
	var versioned *Settings
	if kind == "settings" {
		if cfg, ok := v.(Settings); ok {
			versioned = &cfg
		}
	} else {
		versioned = next
	}
	if versioned != nil {
		snapshot, marshalErr := json.Marshal(versioned)
		if marshalErr != nil {
			return marshalErr
		}
		if _, err = tx.Exec(insertSnapshot, eventTenant(), fmt.Sprint(versioned.Version), string(snapshot)); err != nil {
			return err
		}
	}
	a := Audit{Actor: ActorFromContext(ctx), ID: ID(), Action: action, Subject: id, Detail: RedactText(detail), CreatedAt: e.clock()}
	if kind == "reviews" {
		if review, ok := v.(Review); ok {
			a.Events, err = e.reviewEvents(tx, review, action)
			if err != nil {
				return err
			}
			// A risk-only carrier is not an ordinary call audit. Human actions
			// retain actor/decision attribution, never the free-text comment.
			omitAudit = review.LogSuppression != nil && len(a.Events) == 0 && action != "review.human"
		}
	}
	if !omitAudit {
		b, err := json.Marshal(a)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(insertRecord, eventTenant(), "audit", a.ID, string(b)); err != nil {
			return err
		}
		// #47 outbox only sees the permitted event set; risk delivery survives.
		if err = e.queueLogDeliveries(tx, b); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err == nil {
		select {
		case e.deliveryWake <- struct{}{}:
		default:
		}
		select {
		case e.kafkaWake <- struct{}{}:
		default:
		}
		if next != nil {
			e.Settings = *next
		}
		if e.Notify != nil {
			e.Notify()
		}
	}
	return err
}
func (e *Engine) commitReview(ctx context.Context, r Review, action string) error {
	return e.change(ctx, "reviews", r.ID, r, action, r.Comment)
}
func (e *Engine) Reviews() ([]Review, error) {
	reviews, err := list[Review](e, "reviews")
	for i := range reviews {
		reviews[i] = normalizeReviewPath(reviews[i])
	}
	return reviews, err
}

type ReviewFilter struct {
	Query      string
	Decision   string
	Execution  string
	ReviewPath string
	SessionID  string
	SessionKey string
	From       string
	To         string
}

type ReviewPage struct {
	Items        []Review `json:"items"`
	Total        int      `json:"total"`
	Page         int      `json:"page"`
	PageSize     int      `json:"pageSize"`
	PendingTotal int      `json:"pendingTotal"`
}

func ReviewListView(r Review) Review {
	r.InputState, r.OutputState = reviewInputState(r), reviewOutputState(r)
	r.Scripts = append([]ReviewScript(nil), r.Scripts...)
	for i := range r.Scripts {
		r.Scripts[i].Content = ""
	}
	r.ModelInput = nil
	return r
}

func (e *Engine) ReviewsPage(page, pageSize int, filter ReviewFilter) (ReviewPage, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	where := []string{"r.tenant_id=$1", "r.kind='reviews'"}
	args := []any{eventTenant()}
	add := func(expr string, value any) {
		where = append(where, strings.ReplaceAll(expr, "?", fmt.Sprintf("$%d", len(args)+1)))
		args = append(args, value)
	}
	if filter.Decision != "" {
		add(e.jsonField("r.", "decision")+"=?", filter.Decision)
	}
	if filter.Execution != "" {
		add(e.jsonField("r.", "execution")+"=?", filter.Execution)
	}
	if filter.ReviewPath != "" {
		add(e.jsonField("r.", "reviewPath")+"=?", filter.ReviewPath)
	}
	if filter.SessionID != "" {
		add(e.jsonField("r.", "sessionId")+"=?", eventIdentifier(filter.SessionID))
	}
	if filter.SessionKey != "" {
		add(e.jsonField("r.", "sessionId")+"=?", filter.SessionKey)
	}
	stamp := e.jsonField("r.", "createdAt")
	instant := sqliteSessionInstant(stamp)
	if e.postgres {
		instant = postgresSessionInstant(stamp)
	}
	if filter.From != "" {
		if from, err := sessionBound(filter.From, false); err == nil {
			add(instant+">=?", from.Format(sessionInstantLayout))
		} else {
			add(stamp+">=?", filter.From)
		}
	}
	if filter.To != "" {
		// Plan #16 A3: dates include the UTC day; instant bounds are exclusive.
		if end, err := sessionBound(filter.To, true); err == nil {
			add(instant+"<?", end.Format(sessionInstantLayout))
		} else {
			// API callers validate dates before reaching the engine; preserve the
			// previous comparison for internal callers that pass an invalid value.
			add(stamp+"<?", filter.To+"T00:00:00Z")
		}
	}
	if strings.TrimSpace(filter.Query) != "" {
		needle := strings.ToLower(strings.TrimSpace(filter.Query))
		if e.postgres {
			where = append(where, fmt.Sprintf("(strpos(lower(r.id), $%d) > 0 OR strpos(lower(r.payload), $%d) > 0)", len(args)+1, len(args)+2))
		} else {
			where = append(where, fmt.Sprintf("(instr(lower(r.id), $%d) > 0 OR instr(lower(r.payload), $%d) > 0)", len(args)+1, len(args)+2))
		}
		args = append(args, needle, needle)
	}
	clause := " WHERE " + strings.Join(where, " AND ")
	tx, err := e.beginTenant()
	if err != nil {
		return ReviewPage{}, err
	}
	defer tx.Rollback()
	var total, pending int
	if err := tx.QueryRow("SELECT COUNT(*) FROM records r"+clause, args...).Scan(&total); err != nil {
		return ReviewPage{}, err
	}
	if err := tx.QueryRow("SELECT COUNT(*) FROM records r WHERE r.tenant_id=$1 AND r.kind='reviews' AND "+e.jsonField("r.", "decision")+"='pending' AND CAST("+e.jsonField("r.", "needsHuman")+" AS TEXT) IN ('true','1')", eventTenant()).Scan(&pending); err != nil {
		return ReviewPage{}, err
	}
	offset := (page - 1) * pageSize
	dataArgs := append(append([]any{}, args...), pageSize, offset)
	rows, err := tx.Query("SELECT r.payload FROM records r"+clause+" ORDER BY "+e.jsonField("r.", "createdAt")+fmt.Sprintf(" DESC NULLS LAST, r.id DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2), dataArgs...)
	if err != nil {
		return ReviewPage{}, err
	}
	defer rows.Close()
	items := []Review{}
	for rows.Next() {
		var b []byte
		var review Review
		if err := rows.Scan(&b); err != nil {
			return ReviewPage{}, err
		}
		if err := json.Unmarshal(b, &review); err != nil {
			return ReviewPage{}, err
		}
		items = append(items, ReviewListView(normalizeReviewPath(review)))
	}
	if err := rows.Err(); err != nil {
		return ReviewPage{}, err
	}
	return ReviewPage{Items: items, Total: total, Page: page, PageSize: pageSize, PendingTotal: pending}, nil
}
func (e *Engine) Rules() ([]Rule, error) {
	rules, err := list[Rule](e, "rules")
	for i := range rules {
		rules[i] = normalizeRule(rules[i])
	}
	sortRules(rules)
	return rules, err
}
func (e *Engine) Scopes() ([]Scope, error) { return list[Scope](e, "scopes") }
func (e *Engine) Audits() ([]Audit, error) { return list[Audit](e, "audit") }
func (e *Engine) Review(id string) (Review, error) {
	var r Review
	err := e.get("reviews", id, &r)
	return normalizeReviewPath(r), err
}
func (e *Engine) Instances() ([]Instance, error) {
	is, err := list[Instance](e, "instances")
	for j := range is {
		is[j].Online = is[j].State != "disconnected" && e.clock().Sub(is[j].Heartbeat) < 30*time.Second
	}
	return is, err
}
func (e *Engine) ConfigVersions() ([]Settings, error) { return list[Settings](e, "settings_versions") }
func (e *Engine) Config() Settings {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.Settings
	if s.NSFA.Mode == "enforce" && !e.nsfaEnforceAvailable(s.NSFA) {
		s.NSFA.Mode = "monitor"
	}
	s.Model.APIKey = ""
	return s
}
func (e *Engine) SaveSettings(ctx context.Context, s Settings, key *string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s.Mode != "human" && s.Mode != "model" {
		return errors.New("无效审查模式")
	}
	if s.ApprovalSeconds < 10 || s.ApprovalSeconds > 86400 || s.ModelSeconds < 1 || s.ModelSeconds > 120 {
		return errors.New("超时设置超出范围")
	}
	if len(s.Prompt) < 20 || len(s.Prompt) > 32000 {
		return errors.New("提示词应为 20–32000 字符")
	}
	if !hasExact(s.NSFA.Mode, "", "off", "monitor", "enforce") || (s.NSFA.Mode != "" && s.NSFA.Mode != "off" && !nsfaAllowedEndpoint(s.NSFA.Endpoint)) {
		return errors.New("invalid NSFA configuration")
	}
	if err := s.BTPII.validate(); err != nil {
		return err
	}
	// Legacy blank declarations can be saved but never dispatch customer content.
	if !hasExact(s.Model.ProcessingClass, "", ModelProcessingSelfHosted, ModelProcessingExternal) ||
		(s.PromptAttack.Model != nil && !hasExact(s.PromptAttack.Model.ProcessingClass, "", ModelProcessingSelfHosted, ModelProcessingExternal)) {
		return errors.New("invalid model processing class")
	}
	if err := s.Model.Pricing.validate(); err != nil {
		return err
	}
	if s.Model.Protocol == "" {
		s.Model.Protocol = "openai"
	}
	if !hasExact(s.Model.Protocol, "openai", "anthropic") {
		return errors.New("不支持的模型协议")
	}
	s.Model.APIKey = e.Settings.Model.APIKey
	changed := s.Model.Protocol != e.Settings.Model.Protocol || s.Model.BaseURL != e.Settings.Model.BaseURL || s.Model.Model != e.Settings.Model.Model
	if key != nil && *key != s.Model.APIKey {
		s.Model.APIKey = *key
		changed = true
	}
	s.Model.Tested = e.Settings.Model.Tested && !changed
	if s.Model.BaseURL != "" {
		if err := ValidateModelURL(s.Model.BaseURL); err != nil {
			return err
		}
	}
	if s.Mode == "model" && !s.Model.Tested {
		return errors.New("请先保存模型配置并测试成功，再启用模型审查")
	}
	if s.NSFA.Mode == "enforce" && !e.nsfaEnforceAvailable(s.NSFA) {
		return errors.New("NSFA enforce requires matching NSFA-AVAIL-0 PASS")
	}
	// Invalidation precedes the config write, so even a later store failure cannot
	// retain a stale PASS. Rules/templates do not change sidecar availability.
	if nsfaConfigChanged(e.Settings.NSFA, s.NSFA) {
		if err := e.change(ctx, "nsfa_availability", "current", nil, "nsfa.availability.invalidate", "Sidecar configuration changed; availability proof invalidated"); err != nil {
			return err
		}
		if s.NSFA.Mode == "enforce" {
			s.NSFA.Mode = "monitor"
		}
	}
	if s.NSFA.Mode == "enforce" && !e.nsfaEnforceAvailable(s.NSFA) {
		return errors.New("NSFA enforce requires matching NSFA-AVAIL-0 PASS")
	}
	// Only the enabled bit is input. Preserve attribution until it actually changes.
	enabled := s.ExternalProcessing.Enabled
	s.ExternalProcessing = e.Settings.ExternalProcessing
	if enabled != s.ExternalProcessing.Enabled {
		now := e.clock()
		s.ExternalProcessing = ExternalProcessingConsent{Enabled: enabled, Actor: ActorFromContext(ctx), UpdatedAt: &now}
	}
	s.Model.HasKey = s.Model.APIKey != ""
	s.Version = e.Settings.Version + 1
	if key != nil {
		if err := AtomicFile(filepath.Join(e.Dir, "model.key"), []byte(s.Model.APIKey), 0600); err != nil {
			return err
		}
	}
	if err := e.change(ctx, "settings", "current", s, "settings.update", fmt.Sprintf("配置版本 %d，模式 %s", s.Version, s.Mode)); err != nil {
		if key != nil {
			if rollbackErr := AtomicFile(filepath.Join(e.Dir, "model.key"), []byte(e.Settings.Model.APIKey), 0600); rollbackErr != nil {
				return fmt.Errorf("配置保存失败且密钥回滚失败，请重新保存密钥")
			}
		}
		return err
	}
	e.Settings = s
	return nil
}
func AtomicFile(path string, b []byte, mode os.FileMode) error {
	return atomicFile(path, b, mode, syncDirectory)
}

// The callback makes the post-rename durability boundary fault-testable without
// process-global hooks. Errors after rename mean the new bytes may be visible.
func atomicFile(path string, b []byte, mode os.FileMode, syncDir func(string) error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".aegis-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}
func (e *Engine) sweepLoop() {
	defer e.workers.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
			e.Expire()
		}
	}
}
func (e *Engine) Expire() {
	e.mu.Lock()
	defer e.mu.Unlock()
	rs, err := e.Reviews()
	if err != nil {
		return
	}
	instances, err := e.Instances()
	if err != nil {
		return
	}
	online := map[string]bool{}
	for _, i := range instances {
		online[i.ID] = i.Online
	}
	for _, r := range rs {
		if r.Decision != "pending" {
			continue
		}
		action := ""
		if e.clock().After(r.Deadline) {
			r.RuleID = "E_TIMEOUT"
			r.Comment = "审查等待超时，本次调用已拒绝。"
			action = "review.timeout"
		} else if !online[r.InstanceID] {
			r.RuleID = "E_SESSION"
			r.Comment = "原会话已失联，本次审查已取消，请重新提交。"
			action = "review.cancel"
		}
		if action != "" {
			r.Decision = "reject"
			r.NeedsHuman = false
			r.Execution = "not_executed"
			now := e.clock()
			r.DecidedAt = &now
			e.commitReview(WithActor(context.Background(), SystemActor("review-expiry")), r, action)
		}
	}
}

// fsync the directory entry as well as the data: rename alone is not a durable
// commit. https://lwn.net/Articles/322823/ and golang/go#20599 (Close != Sync).
// Windows does not support directory fsync through os.File; retain Go's file
// sync/rename behavior there, without claiming POSIX power-loss durability.
func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

// The server retains sequential trust history for per-version retrieval. Unlike
// endpoint TrustState this is not subject to D6's two-record persistence bound.
type bundleManifest struct {
	Records []SignedTrustRecord `json:"records"`
	Signer  string              `json:"signer"`
}

func (e *Engine) readBundleManifest() (bundleManifest, error) {
	data, err := os.ReadFile(filepath.Join(e.Dir, "bundle-trust.json"))
	if err != nil {
		return bundleManifest{}, err
	}
	var manifest bundleManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return bundleManifest{}, err
	}
	return manifest, nil
}

func (e *Engine) writeBundleManifest(manifest bundleManifest, write func(string, []byte, os.FileMode) error) error {
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return write(filepath.Join(e.Dir, "bundle-trust.json"), data, 0600)
}
