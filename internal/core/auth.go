package core

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
)

// Principal uses OIDC Core §5.7's stable identity; names/emails are display-only.
type Principal struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleAuditor  Role = "auditor"
	RoleReadOnly Role = "readonly"
)

type Actor struct {
	Issuer    string `json:"issuer,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Name      string `json:"name,omitempty"`
	Kind      string `json:"kind"`
	Component string `json:"component,omitempty"`
}

func SystemActor(component string) Actor {
	return Actor{Kind: "system", Component: component}
}

type actorContextKey struct{}

func WithActor(ctx context.Context, actor Actor) context.Context {
	return context.WithValue(ctx, actorContextKey{}, actor)
}

// ActorFromContext keeps missing attribution visible during the S1→S3 rollout.
// S3 attaches session actors to HTTP contexts and must prove no HTTP mutation
// remains unattributed. Known non-request writers always name their component.
func ActorFromContext(ctx context.Context) Actor {
	if actor, ok := ctx.Value(actorContextKey{}).(Actor); ok && actor.Kind != "" {
		return actor
	}
	return SystemActor("unattributed")
}

// AdminBinding is the host-local recovery override from plan §3.6b (Grafana's
// host-local admin recovery precedent). It is not an IdP role or session store.
type AdminBinding struct {
	Principal
	Name string `json:"name,omitempty"`
}

func (e *Engine) adminBindings() ([]AdminBinding, error) {
	b, err := os.ReadFile(filepath.Join(e.Dir, "admin-bindings.json"))
	if errors.Is(err, os.ErrNotExist) {
		return []AdminBinding{}, nil
	}
	if err != nil {
		return nil, err
	}
	var bindings []AdminBinding
	if err := json.Unmarshal(b, &bindings); err != nil {
		return nil, errors.New("invalid admin bindings")
	}
	for _, binding := range bindings {
		if binding.Issuer == "" || binding.Subject == "" {
			return nil, errors.New("invalid admin binding principal")
		}
	}
	return bindings, nil
}

func (e *Engine) IsRecoveryAdmin(principal Principal) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	bindings, err := e.adminBindings()
	return slices.ContainsFunc(bindings, func(b AdminBinding) bool { return b.Principal == principal }), err
}

func (e *Engine) BindAdmin(principal Principal, name string) error {
	return e.updateAdminBinding(principal, name, false)
}

func (e *Engine) UnbindAdmin(principal Principal) error {
	return e.updateAdminBinding(principal, "", true)
}

func (e *Engine) updateAdminBinding(principal Principal, name string, remove bool) error {
	if principal.Issuer == "" || principal.Subject == "" {
		return errors.New("admin binding requires issuer and subject")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	bindings, err := e.adminBindings()
	if err != nil {
		return err
	}
	index := slices.IndexFunc(bindings, func(binding AdminBinding) bool { return binding.Principal == principal })
	if (remove && index < 0) || (!remove && index >= 0 && bindings[index].Name == name) {
		return nil
	}
	next := make([]AdminBinding, 0, len(bindings))
	for _, binding := range bindings {
		if binding.Principal != principal {
			next = append(next, binding)
		}
	}
	if !remove {
		next = append(next, AdminBinding{Principal: principal, Name: name})
	}
	return e.commitAdminBindings(principal, next, remove)
}

func (e *Engine) commitAdminBindings(principal Principal, next []AdminBinding, remove bool) error {
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(e.Dir, "admin-bindings.json")
	previous, readErr := os.ReadFile(path)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	// As in InstallAgent: write the file, then commit resource + audit, restoring
	// the original file if either step fails. This is compensation, not crash atomicity.
	err = AtomicFile(path, append(b, '\n'), 0600)
	if err == nil {
		action := "admin.bind"
		if remove {
			action = "admin.unbind"
		}
		// Same host-local identity as server.cliSession (plan §3.6a), not the target principal.
		ctx := WithActor(context.Background(), Actor{Issuer: "local", Subject: "cli", Name: "cli", Kind: "cli"})
		err = e.change(ctx, "admin-bindings", "current", next, action, string(mustJSON(principal)))
	}
	if err != nil {
		var restoreErr error
		if errors.Is(readErr, os.ErrNotExist) {
			restoreErr = os.Remove(path)
			if errors.Is(restoreErr, os.ErrNotExist) {
				restoreErr = nil
			}
		} else {
			restoreErr = AtomicFile(path, previous, 0600)
		}
		return errors.Join(err, restoreErr)
	}
	return nil
}
