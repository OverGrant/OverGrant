"""Scanner inputs stay inert and secret values never reach any output format."""

import json
import os
from pathlib import Path

import pytest

from overgrant import cli, discover, report, rules


def write(root, name, data):
    file = root / name
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps(data) if isinstance(data, dict) else data, encoding="utf-8")
    return file


@pytest.mark.parametrize("format", ["text", "json", "sarif"])
def test_no_secret_fixture_value_in_any_output(format, repo, fake_home, capsys):
    secrets = [
        "synthetic-plain-env-secret-123456", "synthetic-header-secret-234567",
        "synthetic-http-header-secret-345678", 'synthetic-quoted-"secret"-\\-\n-456789',
        "sk-ant-SyntheticOnly567890", "sk-proj-SyntheticOnly678901", "ghp_SyntheticOnly789012",
        "gho_SyntheticOnly890123", "github_pat_SyntheticOnly901234", "glpat-SyntheticOnly012345",
        "xoxb-SyntheticOnly123456", "xoxp-SyntheticOnly234567", "AKIA" + "Z" * 16,
        "AIza" + "z" * 35,
    ]
    write(repo, ".mcp.json", {"mcpServers": {"demo": {
        "command": "synthetic-server", "args": secrets,
        "url": "https://example.invalid/" + secrets[0],
        "env": {"TOKEN": secrets[0], "PASSWORD": secrets[3]},
        "headers": {"Authorization": secrets[1]},
        "http_headers": {"X-API-KEY": secrets[2]},
    }}})
    write(repo, ".cursor/sandbox.json", {
        "readBoundary": secrets[1], "additionalReadPaths": ["/synthetic/" + secrets[2]],
    })
    write(repo, ".claude/settings.json", {"nested": secrets[4:]})
    write(fake_home, ".codex/config.toml", '[mcp_servers.demo.env]\n'
          'TOKEN = "synthetic-home-secret-567890"')
    secrets.append("synthetic-home-secret-567890")
    cli.main(["scan", str(repo), "--home", "--format", format])
    captured = capsys.readouterr()
    assert not captured.err
    output = captured.out
    for secret in secrets:
        assert secret not in output
        # Also guard escaped values in the machine-readable formats and embedded details.
        assert json.dumps(secret)[1:-1] not in output
        if format != "text":
            assert secret not in json.dumps(json.loads(output), ensure_ascii=False)
    assert "length " in output and "…" in output


@pytest.mark.parametrize("format", ["text", "json", "sarif"])
def test_secret_server_names_and_paths_are_redacted(format, repo):
    secret = "ghp_SyntheticNameOnly123456789"
    write(repo, ".mcp.json", {"mcpServers": {secret: {
        "command": "server", "env": {secret: secret},
    }}})
    output = report.render(rules.scan(repo), format)
    assert secret not in output


@pytest.mark.parametrize("name,content,kind,line", [
    (".mcp.json", '{\n"token": "ghp_SyntheticMalformed123456"\n "bad":}', "JSON", 3),
    (".codex/config.toml", 'token = "ghp_SyntheticMalformed123456"\nbad = @private', "TOML", 2),
])
@pytest.mark.parametrize("format", ["text", "json", "sarif"])
def test_malformed_input_never_echoes_content(name, content, kind, line, format, repo):
    path = write(repo, name, content)
    result = rules.scan(repo)
    assert result["notes"] == [f"file {path} is not valid {kind} (line {line})"]
    output = report.render(result, format)
    assert "ghp_SyntheticMalformed123456" not in output
    assert "private" not in output.replace(str(repo), "")
    assert content not in output


@pytest.mark.parametrize("directory", [False, True], ids=["file", "parent-directory"])
def test_repo_symlinks_are_reported_without_reading(directory, repo, tmp_path):
    external = tmp_path / "external"
    external.mkdir()
    target = write(external, "settings.json", {"hooks": {"must-not-run": []},
                                             "marker": "ghp_SyntheticUnread123456"})
    if directory:
        (repo / ".claude").symlink_to(external, target_is_directory=True)
    else:
        (repo / ".claude").mkdir()
        (repo / ".claude/settings.json").symlink_to(target)
    result = rules.scan(repo)
    assert result["findings"]
    assert {finding["rule_id"] for finding in result["findings"]} == {"GEN001"}
    assert "SyntheticUnread" not in report.to_json(result)


def test_dangling_config_symlink_is_reported(repo):
    (repo / ".mcp.json").symlink_to(repo / "nonexistent")
    assert [f["rule_id"] for f in rules.scan(repo)["findings"]] == ["GEN001"]


def test_symlinked_repo_root_matches_resolved_root(repo, tmp_path):
    write(repo, ".claude/settings.json", {"hooks": {}})
    link = tmp_path / "linked-repo"
    link.symlink_to(repo, target_is_directory=True)
    assert rules.scan(link) == rules.scan(repo)


def test_symlinked_repo_still_adds_explicit_home_scope(repo, tmp_path, fake_home):
    write(fake_home, ".claude/settings.json", {"permissions": {"defaultMode": "bypassPermissions"}})
    link = tmp_path / "linked-repo"
    link.symlink_to(repo, target_is_directory=True)
    assert {f["rule_id"] for f in rules.scan(link, True)["findings"]} == {"CC001"}


def test_cursor_boundary_values_are_preserved_and_redacted(repo):
    secret = "ghp_SyntheticBoundary123456"
    boundary = {"paths": ["/synthetic/read"], "nested": {"secret": secret}}
    write(repo, ".cursor/sandbox.json", {"readBoundary": boundary,
                                         "additionalReadPaths": ["/synthetic/extra"]})
    finding = next(f for f in rules.scan(repo)["findings"] if f["rule_id"] == "CU001")
    details = json.loads(finding["details"])
    assert details["readBoundary"]["paths"] == ["/synthetic/read"]
    assert details["additionalReadPaths"] == ["/synthetic/extra"]
    assert details["readBoundary"]["nested"]["secret"] == rules.redact_secret(secret)


def test_excessively_nested_configuration_does_not_crash(repo):
    write(repo, ".cursor/sandbox.json", '{"readBoundary": ' + "[" * 2000 + "0" + "]" * 2000 + "}")
    result = rules.scan(repo)
    assert result["findings"][0]["rule_id"] == "CU001"


def test_symlink_swap_cannot_redirect_read(repo, tmp_path, monkeypatch):
    target = write(tmp_path, "outside.json", {"marker": "ghp_SyntheticOutside123456"})
    config = write(repo, ".mcp.json", {})
    original_open = os.open

    def racing_open(path, flags, *args, **kwargs):
        if path == ".mcp.json" and "dir_fd" in kwargs:
            config.unlink()
            config.symlink_to(target)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", racing_open)
    result = rules.scan(repo)
    assert [f["rule_id"] for f in result["findings"]] == ["GEN001"]
    assert "SyntheticOutside" not in report.to_json(result)


def test_files_larger_than_five_mb_are_skipped_with_note(repo):
    config = write(repo, ".mcp.json", "")
    with config.open("wb") as stream:
        stream.write(b'{"mcpServers": {"demo": {"command": "npx"}}, "padding": "')
        stream.seek(discover.MAX_BYTES + 1)
        stream.write(b'"}')
    result = rules.scan(repo)
    assert [f["rule_id"] for f in result["findings"]] == ["MCP004"]
    assert result["notes"] == [f"file {config} exceeds 5 MB; skipped"]


def test_exactly_five_mb_is_allowed(repo):
    write(repo, ".claude/settings.json", "{}" + " " * (discover.MAX_BYTES - 2))
    assert rules.scan(repo) == {"findings": [], "notes": []}


def test_home_scope_uses_fake_home_only(repo, fake_home, monkeypatch):
    write(fake_home, ".claude/settings.json", {"permissions": {"defaultMode": "bypassPermissions"}})
    write(fake_home, ".claude.json", {"mcpServers": {}})
    write(fake_home, ".codex/config.toml", 'approval_policy = "never"')
    for name in ("mcp", "permissions", "sandbox"):
        write(fake_home, f".cursor/{name}.json", {})
    # Exercise Path.home's HOME lookup as well as the fixture's explicit Path.home override.
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: cls("~").expanduser()))
    assert Path.home() == fake_home
    original_read = discover._home_read
    reads = []

    def guarded_read(path):
        assert path.is_relative_to(fake_home)
        reads.append(path)
        return original_read(path)

    monkeypatch.setattr(discover, "_home_read", guarded_read)
    assert not rules.scan(repo)["findings"]
    assert not reads
    result = rules.scan(repo, True)
    assert set(reads) == {fake_home / name for name in discover.HOME_FILES}
    assert {finding["rule_id"] for finding in result["findings"]} == {"CC001", "CX002"}


def test_dotenv_contents_are_never_opened(repo, monkeypatch):
    write(repo, ".env.synthetic", "ghp_SyntheticUnreadEnv123456")
    original_open = os.open

    def guarded_open(path, *args, **kwargs):
        assert not str(path).endswith(".env.synthetic")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded_open)
    result = rules.scan(repo)
    assert [f["rule_id"] for f in result["findings"]] == ["CC008"]
    assert "SyntheticUnreadEnv" not in report.to_json(result)


def test_configs_cannot_execute_commands_or_fetch_urls(repo, tmp_path):
    marker = tmp_path / "must-not-exist"
    write(repo, ".claude/settings.json", {
        "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": f"touch {marker}"}]}]},
        "apiKeyHelper": f"touch {marker}",
    })
    write(repo, ".mcp.json", {"mcpServers": {
        "inert": {"command": "sh", "args": ["-c", f"touch {marker}"]},
        "unfetched": {"url": "http://example.invalid/never-fetch"},
    }})
    assert rules.scan(repo)["findings"]
    assert not marker.exists()


@pytest.mark.parametrize("name", [".mcp.json", ".codex/config.toml"])
def test_invalid_utf8_is_reported_without_bytes(repo, name):
    config = write(repo, name, "")
    config.write_bytes(b"\xff\xfeghp_SyntheticInvalidEncoding123")
    result = rules.scan(repo)
    assert "not valid" in result["notes"][0]
    assert "SyntheticInvalidEncoding" not in report.to_json(result)


@pytest.mark.parametrize("data", [[], None, "text", 17, True])
def test_non_object_json_is_skipped_safely(repo, data):
    write(repo, ".mcp.json", json.dumps(data))
    result = rules.scan(repo)
    assert [f["rule_id"] for f in result["findings"]] == ["MCP004"]
    assert len(result["notes"]) == 1


@pytest.mark.parametrize("name,rule", [
    (".mcp.json", "MCP004"), (".cursor/mcp.json", "MCP004"),
    (".codex/config.toml", "CX007"), (".cursor/sandbox.json", "CU001"),
    (".cursor/permissions.json", "CU002"),
])
def test_file_presence_rules_still_apply_to_malformed_files(repo, name, rule):
    write(repo, name, "{not-valid-json-or-toml")
    result = rules.scan(repo)
    assert [f["rule_id"] for f in result["findings"]] == [rule]
    assert len(result["notes"]) == 1


@pytest.mark.parametrize("name", [".mcp.json", ".cursor/mcp.json"])
def test_empty_repo_mcp_file_is_still_reported(repo, name):
    write(repo, name, {})
    assert [f["rule_id"] for f in rules.scan(repo)["findings"]] == ["MCP004"]


@pytest.mark.parametrize("format", ["text", "json", "sarif"])
def test_secret_key_names_are_redacted_before_pointer_escaping(repo, format):
    secret = 'synthetic/secret~with"quotes-and-newline\n123456789'
    write(repo, ".mcp.json", {"mcpServers": {secret: {
        "command": "server", "env": {"API_KEY": secret},
    }}})
    result = rules.scan(repo)
    for finding in result["findings"]:
        pointer = finding["path"].replace("~1", "/").replace("~0", "~")
        assert secret not in pointer
    output = report.render(result, format)
    assert secret not in output and json.dumps(secret)[1:-1] not in output


@pytest.mark.parametrize("data", [None, [], "value", 1, True])
def test_wrong_typed_config_keys_do_not_crash(repo, data):
    write(repo, ".claude/settings.json", {"permissions": data, "env": data})
    write(repo, ".mcp.json", {"mcpServers": {"demo": {
        "command": data, "args": data, "env": data, "url": data,
    }}})
    assert rules.scan(repo)["findings"]


def test_fifo_config_does_not_block(repo):
    os.mkfifo(repo / ".mcp.json")
    result = rules.scan(repo)
    assert [f["rule_id"] for f in result["findings"]] == ["MCP004"]
    assert "could not be read" in result["notes"][0]
