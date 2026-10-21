package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Only the unchanged rule block shipped in v0.1.1 is eligible for migration.
const legacyDataGuardHash = "5866954a28a2abe8b2298bd30334bd4a6c33415d0dd1c38470b1d2cd2a61a184"

func upgradeDataGuard(prompt string) string {
	if strings.Count(prompt, DataGuardStart) != 1 || strings.Count(prompt, DataGuardEnd) != 1 {
		return prompt
	}
	start, end := strings.Index(prompt, DataGuardStart), strings.Index(prompt, DataGuardEnd)
	if end < start {
		return prompt
	}
	end += len(DataGuardEnd)
	block := strings.ReplaceAll(prompt[start:end], "\r\n", "\n")
	digest := sha256.Sum256([]byte(block))
	if hex.EncodeToString(digest[:]) != legacyDataGuardHash {
		return prompt
	}
	return prompt[:start] + DataGuardPrompt + prompt[end:]
}

// SHA-256 of the exact shipped default at aed9b24, without a final newline.
// Match the whole policy, not phrases: operator edits must never be replaced.
const legacyJudgeDefaultHash = "e0cf1aea5372e8777025c8c0ab69baf2bd9ff6f3a4c321ba7bd5a6b09054d8f8"

func upgradeJudgeDefault(prompt string) string {
	normalized := strings.ReplaceAll(prompt, "\r\n", "\n")
	guard := DataGuardPrompt + "\n\n"
	withGuard := strings.Contains(normalized, guard+DataGuardAnchor)
	candidate := normalized
	if withGuard {
		candidate = strings.Replace(candidate, guard+DataGuardAnchor, DataGuardAnchor, 1)
	}
	digest := sha256.Sum256([]byte(candidate))
	if hex.EncodeToString(digest[:]) != legacyJudgeDefaultHash {
		return prompt
	}
	if withGuard {
		return strings.Replace(DefaultPrompt, DataGuardAnchor, guard+DataGuardAnchor, 1)
	}
	return DefaultPrompt
}

func (e *Engine) upgradePrompt() error {
	s := e.Settings
	prompt := upgradeJudgeDefault(upgradeDataGuard(s.Prompt))
	if prompt == s.Prompt {
		return nil
	}
	// Preserve even an initial settings version that predates version snapshots.
	old, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tx, err := e.beginTenant()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(insertSnapshot, eventTenant(), fmt.Sprint(s.Version), string(old)); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.Prompt = prompt
	s.Version++
	if err = e.change(WithActor(context.Background(), SystemActor("prompt-upgrade")), "settings", "current", s, "settings.prompt.upgrade", "更新未自定义的旧版审查提示词或 R7，保留自定义内容与开关状态"); err != nil {
		return err
	}
	e.Settings = s
	return nil
}
