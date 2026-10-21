package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"aegishook/internal/localaddr"
)

// MachineLayout keeps machine maintenance separate from per-user hook installs.
type MachineLayout struct{ Root, Run, Private, Config, Code, Enrolled, Manifest, Connection, Bundle, Rollback, Socket string }

func MachinePaths(root string) MachineLayout {
	p := MachineLayout{Root: root, Run: filepath.Join(root, "run"), Private: filepath.Join(root, "private")}
	p.Config = filepath.Join(p.Private, "config.json")
	p.Code = filepath.Join(p.Private, "setup-code")
	p.Enrolled = filepath.Join(p.Private, "enrolled.json")
	p.Manifest = filepath.Join(p.Private, "client.json")
	p.Connection = filepath.Join(p.Private, "adapter", "connection.json")
	p.Bundle = filepath.Join(p.Private, "adapter", "bundle.json")
	p.Rollback = filepath.Join(p.Private, "rollback")
	p.Socket = filepath.Join(p.Run, "ctl.sock")
	return p
}

func DefaultRoot() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "TG-Sentry")
	}
	// FHS 3.0 §5.12: variable data for add-on packages installed under /opt.
	if runtime.GOOS == "linux" {
		return "/var/opt/tg-sentry"
	}
	return "/Library/Application Support/TG-Sentry"
}
func PackageRoot() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramFiles"), "TG-Sentry")
	}
	// FHS 3.0 §3.13: add-on application software packages.
	if runtime.GOOS == "linux" {
		return "/opt/tg-sentry"
	}
	return "/Library/Application Support/TG-Sentry"
}

// PackageBinary resolves symlinks so a link to a package binary cannot strand hooks.
func PackageBinary(binary, root string) (bool, error) {
	real, err := filepath.EvalSymlinks(binary)
	if err != nil {
		return false, err
	}
	installed, err := os.Stat(root)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// os.SameFile handles native case-insensitive paths as well as symlinks.
	// https://pkg.go.dev/os#SameFile
	for dir := filepath.Dir(real); ; dir = filepath.Dir(dir) {
		st, err := os.Stat(dir)
		if err != nil {
			return false, err
		}
		if os.SameFile(installed, st) {
			return true, nil
		}
		if filepath.Dir(dir) == dir {
			return false, nil
		}
	}
}

// Windows supplies its owner/DACL/reparse checks in S2. Unsupported means refusal.
var ValidateMachinePath = func(path string, private bool) error { return errors.New("machine filesystem validation unavailable") }

type MachineOptions struct {
	Root, Binary, Endpoint, Owner string
	NoCommit, AcknowledgeManaged  bool
	// ValidatePath is the native owner/ACL check; tests use only temporary roots.
	ValidatePath func(path string, private bool) error
	// ManagedFiles overrides the documented admin destinations for isolated tests.
	ManagedFiles []string
}
type MachineConfig struct {
	Endpoint string `json:"endpoint"`
	Owner    string `json:"owner,omitempty"`
}

func MachineOperation(action string, o MachineOptions) (ClientResult, error) {
	result := ClientResult{Action: action, Scope: "machine"}
	switch action {
	case "system-install", "commit", "rollback", "system-uninstall":
	default:
		return result, errors.New("unsupported machine operation")
	}
	if !filepath.IsAbs(o.Root) || filepath.Clean(o.Root) == filepath.VolumeName(o.Root)+string(filepath.Separator) {
		return result, errors.New("machine root must be an absolute non-root directory")
	}
	o.Root = filepath.Clean(o.Root)
	if o.ValidatePath == nil {
		o.ValidatePath = ValidateMachinePath
	}
	p := MachinePaths(o.Root)
	if err := validateMachineTree(o); err != nil {
		return result, err
	}
	if err := os.MkdirAll(o.Root, 0755); err != nil {
		return result, err
	}
	if err := os.MkdirAll(p.Private, 0700); err != nil {
		return result, err
	}
	if err := validateMachineTree(o); err != nil {
		return result, err
	}
	lock, err := os.OpenFile(filepath.Join(p.Private, "client.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return result, err
	}
	defer lock.Close()
	if err = lockProcessFile(lock); err != nil {
		return result, errors.New("machine maintenance already in progress")
	}
	// A terminal snapshot has already been applied. A retry only disposes it.
	if _, err := os.Lstat(p.Rollback + ".cleanup"); err == nil {
		return result, os.RemoveAll(p.Rollback + ".cleanup")
	} else if !os.IsNotExist(err) {
		return result, err
	}
	switch action {
	case "commit":
		return result, machineCommit(p)
	case "rollback":
		return result, machineRollback(p)
	case "system-uninstall":
		return machineUninstall(o, p)
	default:
		return result, machineInstall(o, p)
	}
}

// CERT FIO15-C: validate every existing directory from the filesystem root.
// The native validator permits sticky writable ancestors, not replaceable paths.
func validateMachineTree(o MachineOptions) error {
	p := MachinePaths(o.Root)
	var chain []string
	for dir := p.Private; ; dir = filepath.Dir(dir) {
		chain = append(chain, dir)
		if filepath.Dir(dir) == dir {
			break
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		dir := chain[i]
		st, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !st.IsDir() {
			return errors.New("machine destination is not a real directory")
		}
		if err = o.ValidatePath(dir, false); err != nil {
			return err
		}
	}
	for _, dir := range []string{o.Root, p.Private} {
		if _, err := os.Lstat(filepath.Join(dir, "aegishook.db")); err == nil {
			return errors.New("machine root cannot be a server data directory")
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if _, err := os.Lstat(p.Private); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	return filepath.WalkDir(p.Private, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return o.ValidatePath(path, true)
	})
}

func machineInstall(o MachineOptions, p MachineLayout) error {
	if _, err := os.Stat(p.Rollback); err == nil {
		if machineSnapshotMarked(p, ".rolled-back") {
			return machineDisposeSnapshot(p)
		}
		if !machineSnapshotMarked(p, ".committed") {
			return errors.New("pending machine transaction; explicit commit or rollback required")
		}
		if err = MachineEnrolled(o); err != nil {
			return fmt.Errorf("committed snapshot cleanup requires enrolled status: %w", err)
		}
		return machineCommit(p)
	} else if !os.IsNotExist(err) {
		return err
	}
	config := MachineConfig{}
	if b, err := os.ReadFile(p.Config); err == nil {
		if json.Unmarshal(b, &config) != nil {
			return errors.New("invalid machine configuration")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if o.Endpoint != "" {
		if config.Endpoint != "" && config.Endpoint != o.Endpoint {
			return errors.New("machine endpoint mismatch")
		}
		config.Endpoint = o.Endpoint
	}
	if o.Owner != "" {
		config.Owner = o.Owner
	}
	var err error
	if config.Endpoint != "" {
		config.Endpoint, err = localaddr.Endpoint(config.Endpoint)
		if err != nil {
			return err
		}
	}
	if !filepath.IsAbs(o.Binary) {
		return errors.New("machine binary must be absolute")
	}
	binary, err := os.ReadFile(o.Binary)
	if err != nil {
		return errors.New("cannot read machine binary")
	}
	m := clientManifest{Format: 1, NodeID: ID(), Resources: map[string]string{}}
	if b, err := os.ReadFile(p.Manifest); err == nil {
		if json.Unmarshal(b, &m) != nil || m.Format != 1 || len(m.Entries) != 0 || len(m.NodeID) != 32 {
			return errors.New("invalid machine manifest")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if o.NoCommit {
		if err = machineSnapshot(p); err != nil {
			return err
		}
	}
	options := ClientOptions{Dir: p.Private, Endpoint: config.Endpoint}
	hasConnection := false
	for _, path := range []string{p.Connection, p.Enrolled} {
		if _, err := os.Stat(path); err == nil {
			hasConnection = true
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	var code []byte
	file, err := os.Open(p.Code)
	hasCode := err == nil
	if hasCode {
		code, err = io.ReadAll(io.LimitReader(file, 8193))
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return errors.New("cannot read setup code")
		}
	} else if !os.IsNotExist(err) {
		return errors.New("cannot read setup code")
	}
	if len(code) > 8192 {
		return errors.New("setup code exceeds input budget")
	}
	if hasCode || hasConnection {
		if config.Endpoint == "" {
			return errors.New("endpoint is required for enrollment")
		}
		if !hasConnection {
			options.EnrollmentCode = strings.TrimSpace(string(code))
			if options.EnrollmentCode == "" {
				return errors.New("setup code is empty")
			}
		}
		if err = prepareClientConnection(&options, &m); err != nil {
			return err
		}
		if err = machineRemove(p.Code); err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(p.Connection), 0700); err != nil {
			return err
		}
		data := mustJSON(ClientConnection{Endpoint: options.Endpoint, Token: options.Token, NodeID: m.NodeID, BundlePublicKey: options.BundlePublicKey})
		if err = machineWriteOwned(p.Connection, data, m.Resources["connection.json"]); err != nil {
			return err
		}
		if m.Resources == nil {
			m.Resources = map[string]string{}
		}
		m.Resources["connection.json"] = digestBytes(data)
	}
	if m.Resources == nil {
		m.Resources = map[string]string{}
	}
	m.Resources["binary"] = digestBytes(binary)
	runtimeData := mustJSON(map[string]string{"binary": o.Binary})
	if err = os.MkdirAll(filepath.Join(p.Private, "adapter"), 0700); err != nil {
		return err
	}
	if err = machineWriteOwned(filepath.Join(p.Private, "adapter", "runtime.json"), runtimeData, m.Resources["runtime.json"]); err != nil {
		return err
	}
	m.Resources["runtime.json"] = digestBytes(runtimeData)
	configData := mustJSON(config)
	if err = AtomicFile(p.Config, configData, 0600); err != nil {
		return err
	}
	m.Resources["config.json"] = digestBytes(configData)
	if err = AtomicFile(p.Manifest, mustJSON(m), 0600); err != nil {
		return err
	}
	if err = os.MkdirAll(p.Run, 0755); err != nil {
		return err
	}
	// Only explicit commit may finalize enrollment or a pending MSI transaction.
	return nil
}

// MachineRepair revalidates live enrollment under the maintenance lock. It never
// commits a pending install: only an explicitly committed snapshot is garbage.
func MachineRepair(o MachineOptions) error {
	return MachineRepairContext(context.Background(), o)
}

// MachineRepairContext propagates the control request deadline into enrollment.
func MachineRepairContext(ctx context.Context, o MachineOptions) error {
	if !filepath.IsAbs(o.Root) || filepath.Clean(o.Root) == filepath.VolumeName(o.Root)+string(filepath.Separator) {
		return errors.New("machine root must be an absolute non-root directory")
	}
	if o.ValidatePath == nil {
		o.ValidatePath = ValidateMachinePath
	}
	if err := validateMachineTree(o); err != nil {
		return err
	}
	p := MachinePaths(o.Root)
	lock, err := os.OpenFile(filepath.Join(p.Private, "client.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lockProcessFile(lock); err != nil {
		return errors.New("machine maintenance already in progress")
	}
	if err := MachineEnrolledContext(ctx, o); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Lstat(p.Rollback + ".cleanup"); err == nil {
		return os.RemoveAll(p.Rollback + ".cleanup")
	} else if !os.IsNotExist(err) {
		return err
	}
	if machineSnapshotMarked(p, ".committed") {
		return machineCommit(p)
	}
	return nil
}

func machineWriteOwned(path string, data []byte, hash string) error {
	edit, err := clientRegularEdit(path, data)
	if err != nil {
		return err
	}
	// An interrupted install can have published a resource before its manifest.
	// Exact bytes are already the desired state; never overwrite a different file.
	if edit.existed && hash == "" && bytes.Equal(edit.before, data) {
		return nil
	}
	if edit.existed && (hash == "" || digestBytes(edit.before) != hash) {
		return errors.New("machine resource changed or foreign; not overwritten")
	}
	return applyClientEdit(edit, false)
}
func machineRemove(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func machineSnapshot(p MachineLayout) error {
	if _, err := os.Lstat(p.Rollback); err == nil {
		return errors.New("pending machine transaction; commit or rollback first")
	} else if !os.IsNotExist(err) {
		return err
	}
	temp, err := os.MkdirTemp(p.Private, ".aegis-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	err = filepath.WalkDir(p.Private, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(p.Private, path)
		if path == temp {
			return filepath.SkipDir
		}
		if rel == ".committed" || rel == ".rolled-back" {
			return errors.New("private file conflicts with transaction marker")
		}
		if rel == "." || rel == "enrolled.json" || rel == "setup-code" || rel == "client.lock" {
			return nil
		}
		dest := filepath.Join(temp, rel)
		if entry.IsDir() {
			return os.Mkdir(dest, 0700)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return AtomicFile(dest, b, 0600)
	})
	if err != nil {
		return err
	}
	return os.Rename(temp, p.Rollback)
}
func machineRollback(p MachineLayout) error {
	if _, err := os.Stat(p.Rollback); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if machineSnapshotMarked(p, ".committed") {
		return errors.New("machine transaction already committed; rollback refused")
	}
	if machineSnapshotMarked(p, ".rolled-back") {
		return machineDisposeSnapshot(p)
	}
	// Remove only generated resources absent from the snapshot; leave foreign files.
	for _, rel := range []string{"client.json", "config.json", "adapter/connection.json", "adapter/runtime.json"} {
		if _, err := os.Stat(filepath.Join(p.Rollback, rel)); os.IsNotExist(err) {
			if err = machineRemove(filepath.Join(p.Private, rel)); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	err := filepath.WalkDir(p.Rollback, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(p.Rollback, path)
		// D3: even a stale snapshot must never overwrite/delete the enrollment retry.
		if rel == "." || rel == "enrolled.json" {
			return nil
		}
		dest := filepath.Join(p.Private, rel)
		if entry.IsDir() {
			return os.MkdirAll(dest, 0700)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return AtomicFile(dest, b, 0600)
	})
	if err != nil {
		return err
	}
	if err = AtomicFile(filepath.Join(p.Rollback, ".rolled-back"), []byte("rolled-back\n"), 0600); err != nil {
		return err
	}
	return machineDisposeSnapshot(p)
}

func machineSnapshotMarked(p MachineLayout, marker string) bool {
	b, err := os.ReadFile(filepath.Join(p.Rollback, marker))
	return err == nil && string(b) == strings.TrimPrefix(marker, ".")+"\n"
}

// Publish terminal state by same-directory rename before recursive deletion.
// A crash may remove any marker during deletion; the sibling name remains terminal.
func machineDisposeSnapshot(p MachineLayout) error {
	if err := os.Rename(p.Rollback, p.Rollback+".cleanup"); err != nil {
		return err
	}
	return os.RemoveAll(p.Rollback + ".cleanup")
}

func machineMarkCommitted(p MachineLayout) error {
	if _, err := os.Stat(p.Rollback); err == nil {
		return AtomicFile(filepath.Join(p.Rollback, ".committed"), []byte("committed\n"), 0600)
	} else if !os.IsNotExist(err) {
		return err
	}
	// A PKG commit has no snapshot. Publish its marker and directory together,
	// so a failed marker write cannot leave an empty, apparently pending snapshot.
	temp, err := os.MkdirTemp(p.Private, ".aegis-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	if err = AtomicFile(filepath.Join(temp, ".committed"), []byte("committed\n"), 0600); err != nil {
		return err
	}
	return os.Rename(temp, p.Rollback)
}

func machineCommit(p MachineLayout) error {
	if machineSnapshotMarked(p, ".rolled-back") {
		return machineDisposeSnapshot(p)
	}
	if _, err := os.Stat(p.Enrolled); err == nil {
		if _, err = os.Stat(p.Connection); err != nil {
			return errors.New("cannot discard enrollment before connection is installed")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := machineMarkCommitted(p); err != nil {
		return err
	}
	for _, path := range []string{p.Enrolled, p.Code} {
		if err := machineRemove(path); err != nil {
			return err
		}
	}
	return machineDisposeSnapshot(p)
}

func MachineInstalled(o MachineOptions) bool {
	p := MachinePaths(o.Root)
	b, err := os.ReadFile(p.Manifest)
	var m clientManifest
	if err != nil || json.Unmarshal(b, &m) != nil || m.Format != 1 || len(m.Entries) != 0 {
		return false
	}
	runtimeData, err := os.ReadFile(filepath.Join(p.Private, "adapter", "runtime.json"))
	var r struct{ Binary string }
	if err != nil || m.Resources["runtime.json"] != digestBytes(runtimeData) || json.Unmarshal(runtimeData, &r) != nil {
		return false
	}
	binary, err := os.ReadFile(r.Binary)
	return err == nil && m.Resources["binary"] == digestBytes(binary)
}

// MachineEnrolled uses the existing signed cache and high-water-mark checks.
// ETag handling follows bridge.policyBundle (OPA conditional bundle fetch).
func MachineEnrolled(o MachineOptions) error {
	return MachineEnrolledContext(context.Background(), o)
}

// MachineEnrolledContext uses net/http cancellation for propagated deadlines.
func MachineEnrolledContext(ctx context.Context, o MachineOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p := MachinePaths(o.Root)
	if o.ValidatePath == nil {
		o.ValidatePath = ValidateMachinePath
	}
	if err := validateMachineTree(o); err != nil {
		return err
	}
	b, err := os.ReadFile(p.Connection)
	var conn ClientConnection
	if err != nil || json.Unmarshal(b, &conn) != nil || len(conn.NodeID) != 32 || len(conn.Token) != 64 || len(conn.BundlePublicKey) != ed25519.PublicKeySize {
		return errors.New("machine credential unavailable")
	}
	endpoint, err := localaddr.Endpoint(conn.Endpoint)
	if err != nil {
		return err
	}
	etag := ""
	if previous, err := ReadPolicyBundle(p.Bundle, conn.BundlePublicKey, conn.NodeID); err == nil {
		etag = PolicyBundleETag(previous)
	} else if !os.IsNotExist(err) {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/api/v1/client/bundle", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+conn.Token)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("bundle redirect refused") }}
	res, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("machine bundle service unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotModified {
		if etag != "" && res.Header.Get("ETag") == etag {
			return nil
		}
		return errors.New("bundle 304 without matching cache")
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("machine bundle HTTP %d", res.StatusCode)
	}
	signed, err := DecodePolicyBundle(res.Body)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("invalid machine bundle response")
	}
	if value := res.Header.Get("ETag"); value != "" && value != PolicyBundleETag(signed) {
		return errors.New("machine bundle ETag mismatch")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err = CachePolicyBundle(p.Bundle, signed, conn.BundlePublicKey, conn.NodeID)
	return err
}

func ClientHooksConfigured(home string) bool {
	report, err := ClientDrift(home)
	if err != nil || report.Manifest != ManifestOK || len(report.Entries) == 0 {
		return false
	}
	evaluated := false
	for _, entry := range report.Entries {
		if entry.OwnerState == OwnerNotEvaluated {
			continue
		}
		evaluated = true
		if entry.OwnerState != OwnedExact {
			return false
		}
	}
	return evaluated
}

func machineUninstall(o MachineOptions, p MachineLayout) (ClientResult, error) {
	result := ClientResult{Action: "system-uninstall", Scope: "machine"}
	for _, path := range o.ManagedFiles {
		b, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return result, err
		}
		// JSON/TOML quote Windows backslashes; compare the decoded spelling.
		text := strings.ReplaceAll(string(b), `\\`, `\`)
		text = strings.ReplaceAll(text, `\/`, `/`)
		binary := o.Binary
		if runtime.GOOS == "windows" {
			text, binary = strings.ToLower(text), strings.ToLower(binary)
		}
		if binary != "" && strings.Contains(text, binary) {
			result.Retained = append(result.Retained, path)
		}
	}
	if len(result.Retained) > 0 && !o.AcknowledgeManaged {
		return result, errors.New("managed configuration references package binary; remove it first or --acknowledge-managed")
	}
	// Acknowledged managed files belong to the administrator, never to cleanup.
	result.Retained = nil
	b, err := os.ReadFile(p.Manifest)
	var m clientManifest
	if err != nil || json.Unmarshal(b, &m) != nil || m.Format != 1 || len(m.Entries) != 0 {
		return result, errors.New("machine manifest missing or foreign; retained")
	}
	// Match the installer's validate-before-apply ordering: a refusal must not
	// strand the manifest, credentials or cache by partially cleaning private/.
	result.Retained, err = machineUninstallPreflight(p, m)
	if err != nil {
		return result, err
	}
	if len(result.Retained) > 0 {
		return result, errors.New("machine uninstall retained foreign or modified resources")
	}
	result.Retained = append(result.Retained, removeClientPolicyBundle(p.Private, m.Resources["connection.json"])...)
	if len(result.Retained) > 0 {
		return result, errors.New("machine uninstall retained foreign or modified resources")
	}
	for _, name := range []string{"connection.json", "runtime.json", "config.json"} {
		path := filepath.Join(p.Private, "adapter", name)
		if name == "config.json" {
			path = p.Config
		}
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || m.Resources[name] != digestBytes(data) {
			result.Retained = append(result.Retained, path)
			continue
		}
		if err = machineRemove(path); err != nil {
			return result, err
		}
	}
	if len(result.Retained) == 0 {
		if err = machineRemove(p.Manifest); err != nil {
			return result, err
		}
	}
	result.Retained = append(result.Retained, removeClientPending(p.Private)...)
	if data, err := os.ReadFile(filepath.Join(p.Private, "adapter", "bundle.json.lock")); err == nil && len(data) == 0 {
		if err = machineRemove(filepath.Join(p.Private, "adapter", "bundle.json.lock")); err != nil {
			return result, err
		}
	}
	_ = os.Remove(filepath.Join(p.Private, "adapter"))
	entries, err := os.ReadDir(p.Private)
	if err != nil {
		return result, err
	}
	for _, entry := range entries {
		if entry.Name() != "client.lock" {
			result.Retained = append(result.Retained, filepath.Join(p.Private, entry.Name()))
		}
	}
	if len(result.Retained) > 0 {
		return result, errors.New("machine uninstall retained foreign or modified resources")
	}
	return result, nil
}
