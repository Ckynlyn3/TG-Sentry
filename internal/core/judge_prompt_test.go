package core

import (
	"aegishook/internal/teststore"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func legacyJudgePrompt(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/judge_default_legacy.txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// These are prompt-contract checks, not a claim about a model's accuracy.
func TestDefaultJudgeNeutralRiskPolicy(t *testing.T) {
	for _, forbidden := range []string{"已获授权的渗透测试", "未知脚本、信息不足或对象归属不明本身不是拒绝理由", "默认允许", "cat /etc/shadow\n{\"decision\":\"approve\""} {
		if strings.Contains(DefaultPrompt, forbidden) {
			t.Errorf("default judge retains permissive policy %q", forbidden)
		}
	}
	for _, required := range []string{"最小权限", "提示词注入", "敏感信息", "不能推翻确定性规则的拒绝", DataGuardAnchor, "decision 只能是 approve 或 reject"} {
		if !strings.Contains(DefaultPrompt, required) {
			t.Errorf("default judge missing safety contract %q", required)
		}
	}
	examples := 0
	for _, line := range strings.Split(DefaultPrompt, "\n") {
		if !strings.HasPrefix(line, `{"decision":`) {
			continue
		}
		examples++
		if _, err := ParseModelDecision(line); err != nil {
			t.Errorf("default example violates unchanged parser: %v", err)
		}
	}
	if examples == 0 {
		t.Fatal("default prompt has no parseable output examples")
	}
}

func TestLegacyJudgeDefaultMigration(t *testing.T) {
	legacy := legacyJudgePrompt(t)
	for _, guard := range []bool{false, true} {
		for _, crlf := range []bool{false, true} {
			name := map[bool]string{false: "disabled", true: "enabled"}[guard] + map[bool]string{false: "/lf", true: "/crlf"}[crlf]
			t.Run(name, func(t *testing.T) {
				dir := teststore.Dir(t, t.TempDir())
				e, err := Open(dir)
				if err != nil {
					t.Fatal(err)
				}
				s := e.Config()
				// Reuse the settings version exercised by the existing upgrade tests.
				s.Version = 13
				s.Prompt = legacy
				want := DefaultPrompt
				if guard {
					s.Prompt = strings.Replace(s.Prompt, DataGuardAnchor, DataGuardPrompt+"\n\n"+DataGuardAnchor, 1)
					want = strings.Replace(want, DataGuardAnchor, DataGuardPrompt+"\n\n"+DataGuardAnchor, 1)
				}
				if crlf {
					s.Prompt = strings.ReplaceAll(s.Prompt, "\n", "\r\n")
				}
				if err = e.put("settings", "current", s); err != nil {
					t.Fatal(err)
				}
				e.Close()
				e, err = Open(dir)
				if err != nil {
					t.Fatal(err)
				}
				if e.Config().Prompt != want || e.Config().Version != s.Version+1 {
					t.Error("legacy default not upgraded exactly once with guard toggle preserved")
				}
				var previous Settings
				if err = e.get("settings_versions", "13", &previous); err != nil || previous.Prompt != s.Prompt {
					t.Error("original prompt bytes not preserved in version snapshot", err)
				}
				audits, err := e.Audits()
				if err != nil || len(audits) != 1 || audits[0].Action != "settings.prompt.upgrade" || audits[0].Actor != SystemActor("prompt-upgrade") {
					t.Error("missing existing upgrade audit", err)
				}
				e.Close()
				e, err = Open(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer e.Close()
				if e.Config().Prompt != want || e.Config().Version != s.Version+1 {
					t.Fatal("restart repeated or altered migration")
				}
			})
		}
	}
}

func TestLegacyJudgeCustomizationPreserved(t *testing.T) {
	legacy := legacyJudgePrompt(t)
	withGuard := strings.Replace(legacy, DataGuardAnchor, DataGuardPrompt+"\n\n"+DataGuardAnchor, 1)
	for name, prompt := range map[string]string{
		"custom":          "operator policy",
		"prefix":          "operator prefix\n" + legacy,
		"suffix":          legacy + "\noperator suffix",
		"edited":          strings.Replace(legacy, "AegisHook", "operator", 1),
		"guard-edited":    strings.Replace(withGuard, "R7：", "R7：operator condition; ", 1),
		"guard-duplicate": strings.Replace(withGuard, DataGuardPrompt, DataGuardPrompt+"\n"+DataGuardPrompt, 1),
		"current":         DefaultPrompt,
	} {
		t.Run(name, func(t *testing.T) {
			e := engine(t)
			e.Settings.Prompt = prompt
			before, err := json.Marshal(e.Config())
			if err != nil {
				t.Fatal(err)
			}
			if err := e.upgradePrompt(); err != nil {
				t.Fatal(err)
			}
			after, err := json.Marshal(e.Config())
			if err != nil || string(after) != string(before) {
				t.Fatal("custom/current settings changed", err)
			}
		})
	}
}
