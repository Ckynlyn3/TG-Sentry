#!/usr/bin/env python3
"""Parse actual generator output; never launch Codex or execute hook commands.

Use Python 3.11+ tomllib, or Tomli on older Python (PEP 680's parser precedent).
Input order: config.toml requirements.toml. Generate both with the same paths.
Sources: https://learn.chatgpt.com/docs/hooks#config-shape,
#managed-hooks-from-requirementstoml; config-reference#requirementstoml.
"""
import json
from pathlib import Path
import shlex
import sys

try:
    import tomllib
except ImportError:
    import tomli as tomllib


def verify(config_path, requirements_path):
    config = tomllib.loads(Path(config_path).read_text(encoding="utf-8"))
    managed = tomllib.loads(Path(requirements_path).read_text(encoding="utf-8"))
    assert set(config) == {"hooks"}, "user config must not pretend to enforce policy"
    assert set(managed) == {"allow_managed_hooks_only", "features", "hooks"}
    assert managed["allow_managed_hooks_only"] is True
    assert managed["features"] == {"hooks": True}, "managed hooks must be pinned on"
    managed_hooks = dict(managed["hooks"])
    directory_key = "windows_managed_dir" if "windows_managed_dir" in managed_hooks else "managed_dir"
    directory = managed_hooks.pop(directory_key)
    assert directory, "managed hooks require a directory"
    assert managed_hooks == config["hooks"], "policy and user hook contracts drifted"
    events = {"SessionStart", "PreToolUse", "PostToolUse", "SessionEnd", "UserPromptSubmit"}
    assert set(managed_hooks) == events, "unexpected or missing lifecycle events"
    commands = set()
    for event, groups in managed_hooks.items():
        assert len(groups) == 1 and set(groups[0]) == {"hooks"}
        assert len(groups[0]["hooks"]) == 1
        handler = groups[0]["hooks"][0]
        assert handler["type"] == "command"
        assert handler["timeout"] == (3 if event == "SessionEnd" else 5)
        if "command_windows" in handler:
            assert handler["command_windows"] == handler["command"]
        else:
            words = shlex.split(handler["command"])
            assert words[1:5] == ["hook", "--agent", "codex", "--connection"]
            assert words[0].startswith("/") and words[5].startswith("/")
            assert str(Path(words[0]).parent) == directory
        assert not ({"async", "onFailure"} & set(handler)), "unsupported enforcement field"
        commands.add(handler["command"])
    assert len(commands) == 1, "lifecycle handlers must share one adapter"
    print(json.dumps({"parser": tomllib.__name__, "config": str(config_path),
                      "requirements": str(requirements_path), "events": sorted(events),
                      "managed_only": True, "hooks_pinned_on": True}))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: test-codex-config.py config.toml requirements.toml")
    verify(sys.argv[1], sys.argv[2])
