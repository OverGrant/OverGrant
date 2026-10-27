"""Synthetic regressions for the overgrant security review."""

import io
import json
import os
import sys
from pathlib import Path

import pytest

from overgrant import cli, discover, report, rules


def write(root, name, data):
    file = root / name
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps(data), encoding="utf-8")
    return file


@pytest.mark.parametrize("format", ["text", "json", "sarif"])
@pytest.mark.parametrize("name", [".mcp.json", ".cursor/mcp.json"])
def test_mcp004_does_not_echo_sensitive_launch_details(repo, format, name):
    write(repo, name, {"mcpServers": {
        "key": {"command": "/synthetic/private/bin/npx", "args": [
            "demo", "--api-key", "hunter2hunter2", "-H", "Authorization: Bearer zzTOPSECRETzz",
            "secret=synthetic", "abcdefgh1234", "--short", "abc",
        ]},
        "url": {"url": "https://user:syntheticpass@h/mcp?token=abcd1234secretXYZ#private"},
    }})
    result = rules.scan(repo)
    output = report.render(result, format)
    for secret in ("hunter2hunter2", "zzTOPSECRETzz", "abcd1234secretXYZ", "syntheticpass",
                   "user:", "secret=synthetic", "abcdefgh1234", "/synthetic/private/bin",
                   "#private"):
        assert secret not in output
    descriptions = [json.loads(f["details"]) for f in result["findings"]
                    if f["rule_id"] == "MCP004"]
    local = next(d for d in descriptions if d["server"] == "key")
    assert local["command"] == "npx"
    assert local["packages"] == ["demo"]
    assert local["args"][-1] == "****(len 3)"
    assert next(d for d in descriptions if d["server"] == "url")["url"] == "https://h/mcp"


@pytest.mark.parametrize("command,args", [
    ("npx demo --api-key hunter2hunter2", []),
    ("cmd", ["/c", "npx demo --api-key hunter2hunter2"]),
    ("sh", ["-c", "npx demo --api-key hunter2hunter2"]),
])
def test_mcp004_embedded_command_lines_are_not_echoed(repo, command, args):
    write(repo, ".mcp.json", {"mcpServers": {"demo": {"command": command, "args": args}}})
    output = report.render(rules.scan(repo), "text")
    assert "hunter2hunter2" not in output


def test_symlinked_ancestor_and_home_match_real_paths(repo, fake_home, tmp_path, monkeypatch):
    write(repo, ".claude/settings.json", {"hooks": {}})
    write(fake_home, ".claude/settings.json", {"permissions": {"defaultMode": "bypassPermissions"}})
    write(fake_home, ".codex/config.toml", {"ignored": True})
    # Also verify trust comparison uses the same canonical HOME.
    (fake_home / ".codex/config.toml").write_text(
        f'[projects.{json.dumps(str(fake_home))}]\ntrust_level = "trusted"', encoding="utf-8")
    expected = rules.scan(repo, True)
    alias = tmp_path / "tmp-alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: alias / fake_home.name))
    assert rules.scan(alias / repo.name, True) == expected


def test_roots_are_resolved_once(repo, fake_home, monkeypatch):
    write(repo, ".codex/config.toml", {})
    (repo / ".codex/config.toml").write_text(
        f'[projects.{json.dumps(str(fake_home))}]\ntrust_level = "trusted"', encoding="utf-8")
    original_resolve = Path.resolve
    resolutions = []

    def resolve(path, *args, **kwargs):
        resolutions.append(path)
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)
    assert any(f["rule_id"] == "CX006" for f in rules.scan(repo, True)["findings"])
    assert resolutions.count(repo) == resolutions.count(fake_home) == 1


PRESENCE_FILES = [
    (".mcp.json", "MCP004"), (".cursor/mcp.json", "MCP004"),
    (".codex/config.toml", "CX007"), (".cursor/sandbox.json", "CU001"),
    (".cursor/permissions.json", "CU002"), (".claude/settings.json", "GEN002"),
    (".claude/settings.local.json", "GEN002"),
]


@pytest.mark.parametrize("name,rule_id", PRESENCE_FILES)
@pytest.mark.parametrize("state", ["oversized", "unreadable", "malformed", "encoding", "shape",
                                   "grew-during-read"])
def test_uninspectable_repo_configs_keep_presence_findings(repo, name, rule_id, state,
                                                          monkeypatch, capsys):
    file = write(repo, name, {})
    if state == "oversized":
        with file.open("wb") as stream:
            stream.truncate(discover.MAX_BYTES + 1)
    elif state == "unreadable":
        original_open = os.open

        def denied_open(path, *args, **kwargs):
            if path == file.name and "dir_fd" in kwargs:
                raise PermissionError("synthetic denial")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr(os, "open", denied_open)
    elif state == "malformed":
        file.write_text("{invalid", encoding="utf-8")
    elif state == "encoding":
        file.write_bytes(b"\xff\xfe")
    elif state == "shape":
        file.write_text("[]" if file.suffix == ".json" else "[broken", encoding="utf-8")
    else:
        original_read = discover._repo_read

        def growing_read(root_fd, requested):
            return b" " * (discover.MAX_BYTES + 1) if requested == name else original_read(
                root_fd, requested)

        monkeypatch.setattr(discover, "_repo_read", growing_read)
    result = rules.scan(repo)
    assert [f["rule_id"] for f in result["findings"]] == [rule_id]
    assert len(result["notes"]) == 1
    if rule_id == "GEN002":
        assert result["findings"][0]["severity"] == "high"
        assert cli.main(["scan", str(repo), "--fail-on", "high"]) == 1
        assert "GEN002" in capsys.readouterr().out


@pytest.mark.parametrize("format", ["text", "json", "sarif"])
def test_lone_surrogates_in_config_and_filename_are_safe(repo, monkeypatch, format):
    write(repo, ".cursor/sandbox.json", {"readBoundary": "value-\ud800"})
    result = rules.scan(repo)
    # macOS rejects invalid UTF-8 filenames; simulate a surrogate-escaped name
    # supplied by a filesystem that permits them, after scanning real JSON.
    result["findings"][0]["file"] += "\udcff"
    rendered = report.render(result, format)
    rendered.encode("utf-8", errors="strict")
    assert "\\ud800" in rendered
    assert ("%5Cudcff" if format == "sarif" else "\\udcff") in rendered
    output = io.BytesIO()
    stream = io.TextIOWrapper(output, encoding="ascii", errors="strict")
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(rules, "scan", lambda *args: result)
    assert cli.main(["scan", str(repo), "--format", format]) == 1
    assert output.getvalue().decode("utf-8").strip() == rendered
    if format != "text":
        json.loads(output.getvalue())


@pytest.mark.parametrize("command,prefix", [
    ("cmd", ["/c"]), ("sh", ["-c"]), ("bash", ["-c"]),
    ("/bin/bash", ["-c"]), ("env", ["-u", "IGNORED", "MODE=synthetic"]),
    ("npm", ["exec"]), ("uv", ["tool", "run"]), ("yarn", ["dlx"]),
])
@pytest.mark.parametrize("pinned", [False, True])
def test_wrapped_launchers(repo, command, prefix, pinned):
    package = "demo@1.2.3" if pinned else "demo"
    if command in ("cmd", "sh", "bash", "/bin/bash"):
        args = [*prefix, f'npx "{package}"']
    elif command == "env":
        args = [*prefix, "npx", package]
    elif command == "uv":
        args = [*prefix, "demo==1.2.3" if pinned else "demo"]
    else:
        args = [*prefix, package]
    write(repo, ".mcp.json", {"mcpServers": {"demo": {"command": command, "args": args}}})
    assert any(f["rule_id"] == "MCP002" for f in rules.scan(repo)["findings"]) is not pinned


@pytest.mark.parametrize("command,args,unpinned", [
    ("uvx", ["--with", "dep", "demo==1.2.3"], True),
    ("uvx", ["--with", "dep==1.0", "demo"], True),
    ("uvx", ["--with", "dep==1.0", "demo==1.2.3"], False),
    ("uvx", ["--with=dep==1.0", "--from", "demo==1.2.3", "binary"], False),
    ("uvx", ["--from", "demo", "binary"], True),
    ("uvx", ["--from=demo==1.2.3", "binary"], False),
    ("env", ["--", "bash", "-c", "npm exec --package=demo binary"], True),
    ("cmd.exe", ["/c", "npx", "demo"], True),
    ("bash", ["-c", 'npx "demo@1.2.3"', "unrelated"], False),
    ("bash", ["-c", 'npx "unterminated'], False),
])
def test_launcher_value_options_and_nested_wrappers(command, args, unpinned):
    assert rules.launcher_unpinned(command, args) is unpinned


@pytest.mark.parametrize("secret", ["x", "abcd", "abcdefg", "abcdefgh"])
def test_short_secrets_are_masked_and_do_not_corrupt_other_text(repo, secret):
    write(repo, ".mcp.json", {"mcpServers": {"demo": {"env": {"TOKEN": secret}}}})
    finding = next(f for f in rules.scan(repo)["findings"] if f["rule_id"] == "MCP001")
    assert finding["details"] == f"****(len {len(secret)})"
    redactor = rules.Redactor()
    redactor.secrets.add(secret)
    assert redactor.redact(secret) == f"****(len {len(secret)})"
    if len(secret) < 8:
        assert redactor.redact(f"prefix-{secret}-suffix") == f"prefix-{secret}-suffix"
    assert finding["source"] == rules.CC_MCP


@pytest.mark.parametrize("token", [
    "ghp_abc.TAIL", "ghp_abc/TAIL+=.-", "sk-ant-abc.TAIL", "ghp_abc!TAIL",
])
@pytest.mark.parametrize("format", ["text", "json", "sarif"])
def test_entire_known_token_is_redacted_through_punctuation(repo, token, format):
    write(repo, ".claude/settings.json", {"value": "Bearer " + token})
    output = report.render(rules.scan(repo), format)
    assert token not in output and "TAIL" not in output
    redactor = rules.Redactor()
    redactor.secrets.add(token.split(".")[0])
    assert "TAIL" not in redactor.redact(token)


@pytest.mark.parametrize("value,secret", [
    ("${TOKEN}", False), ("${env:TOKEN}", False), ("${TOKEN:-}", False),
    ("${TOKEN:-${env:BACKUP}}", False), ("${TOKEN:-syntheticsecret}", True),
    ("prefix-${TOKEN}", True), ("${TOKEN}-suffix", True), ("${TOKEN}${OTHER}", True),
    ("${not a variable}", True), (0, True), (12345, True), (1.25, True),
])
def test_mcp001_interpolation_and_numbers(repo, value, secret):
    write(repo, ".mcp.json", {"mcpServers": {"demo": {"env": {"API_TOKEN": value}}}})
    matching = [f for f in rules.scan(repo)["findings"] if f["rule_id"] == "MCP001"]
    assert bool(matching) is secret
    if secret:
        assert matching[0]["details"] == rules.redact_secret(str(value))


@pytest.mark.parametrize("key,secret", [
    ("TOKEN", True), ("APIKEY", True), ("my_api_key", True), ("accessToken", True),
    ("client-secret", True), ("HTTP_AUTH", True), ("PASSWORD", True),
    ("MONKEY", False), ("KEYBOARD", False), ("TOKENIZER", False), ("AUTHOR", False),
    ("NO_AUTH", False), ("noAuth", False), ("SOME_NO_AUTH", False),
])
def test_mcp001_key_word_segments(repo, key, secret):
    write(repo, ".mcp.json", {"mcpServers": {"demo": {"env": {key: 1}}}})
    assert any(f["rule_id"] == "MCP001" for f in rules.scan(repo)["findings"]) is secret


@pytest.mark.parametrize("entry", [
    "Bash(bash -c *)", "Bash(python3.12:*)", "Bash(python3.12 *)",
    "Bash(/bin/sh:*)", "Bash(/bin/sh *)", "Bash(/usr/bin/python3:*)",
    "Bash(/usr/bin/python3 *)", "Bash(python3 -c *)", "Bash(/bin/bash -c *)",
    "Bash(/usr/bin/python3.12 -c *)",
])
def test_cc003_interpreter_paths_versions_and_code_flags(repo, entry):
    write(repo, ".claude/settings.json", {"permissions": {"allow": [entry]}})
    assert [f["rule_id"] for f in rules.scan(repo)["findings"]] == ["CC003"]


@pytest.mark.parametrize("size", [5 * 1024 * 1024 + 1, 50 * 1024 * 1024])
def test_home_claude_json_accepts_up_to_fifty_mb(repo, fake_home, size):
    file = write(fake_home, ".claude.json", {
        "mcpServers": {"demo": {"url": "http://example.invalid/mcp"}},
    })
    with file.open("ab") as stream:
        stream.write(b" " * (size - file.stat().st_size))
    result = rules.scan(repo, True)
    assert [f["rule_id"] for f in result["findings"]] == ["MCP003"]
    assert result["notes"] == []


def test_home_claude_json_over_fifty_mb_is_skipped(repo, fake_home):
    file = write(fake_home, ".claude.json", {})
    with file.open("ab") as stream:
        stream.truncate(50 * 1024 * 1024 + 1)
    result = rules.scan(repo, True)
    assert result["notes"] == [f"file {file} exceeds 50 MB; skipped"]


def test_other_home_files_keep_five_mb_limit(repo, fake_home):
    file = write(fake_home, ".claude/settings.json", {})
    with file.open("ab") as stream:
        stream.truncate(5 * 1024 * 1024 + 1)
    assert rules.scan(repo, True)["notes"] == [f"file {file} exceeds 5 MB; skipped"]


@pytest.mark.parametrize("name", [
    ".env.example", ".env.sample", ".env.template", ".env.local.example",
    ".env.production.sample", ".envrc",
])
def test_cc008_ignores_examples_and_direnv(repo, name, monkeypatch):
    file = write(repo, name, "synthetic example")
    original_open = os.open

    def guarded_open(path, *args, **kwargs):
        assert str(path) not in (name, str(file))
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded_open)
    assert rules.scan(repo) == {"findings": [], "notes": []}


@pytest.mark.parametrize("name", [".env", ".env.local", ".env.production", ".env.example.local"])
def test_cc008_still_detects_actual_dotenv_files(repo, name):
    write(repo, name, "synthetic")
    assert [f["rule_id"] for f in rules.scan(repo)["findings"]] == ["CC008"]
