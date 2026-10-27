"""Each rule has both a positive and a negative synthetic fixture."""

import json
from pathlib import Path

import pytest

from overgrant import rules


def write(root, name, data):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data) if isinstance(data, dict) else data, encoding="utf-8")
    return path


CASES = [
    ("CC001", "user", ".claude/settings.json",
     {"permissions": {"defaultMode": "bypassPermissions"}},
     {"permissions": {"defaultMode": "auto"}}),
    ("CC002", "repo", ".claude/settings.json",
     {"permissions": {"defaultMode": "auto"}}, {"permissions": {"defaultMode": "default"}}),
    ("CC003", "repo", ".claude/settings.json",
     {"permissions": {"allow": ["Bash(python:*)"]}},
     {"permissions": {"allow": ["Bash(pytest tests)"]}}),
    ("CC004", "repo", ".claude/settings.local.json", {"hooks": {}}, {}),
    ("CC005", "repo", ".claude/settings.json", {"apiKeyHelper": "synthetic-helper"}, {}),
    ("CC006", "repo", ".claude/settings.json",
     {"env": {"ANTHROPIC_BASE_URL": "https://example.invalid"}},
     {"env": {"ORDINARY_SETTING": "value"}}),
    ("CC007", "user", ".claude/settings.json",
     {"enableAllProjectMcpServers": True}, {"enableAllProjectMcpServers": False}),
    ("CC008", "repo", ".claude/settings.json",
     {"permissions": {"deny": []}}, {"permissions": {"deny": ["Read(./.env*)"]}}),
    ("MCP001", "repo", ".mcp.json",
     {"mcpServers": {"demo": {"env": {"API_TOKEN": "synthetic-literal-value"}}}},
     {"mcpServers": {"demo": {"env": {"API_TOKEN": "${TOKEN_FROM_ENV}"}}}}),
    ("MCP002", "repo", ".mcp.json",
     {"mcpServers": {"demo": {"command": "npx", "args": ["-y", "@demo/tool"]}}},
     {"mcpServers": {"demo": {"command": "npx", "args": ["-y", "@demo/tool@1.2.3"]}}}),
    ("MCP003", "repo", ".mcp.json",
     {"mcpServers": {"demo": {"url": "http://example.invalid/mcp"}}},
     {"mcpServers": {"demo": {"url": "http://localhost:9000/mcp"}}}),
    ("MCP004", "repo", ".mcp.json",
     {"mcpServers": {"demo": {"command": "synthetic-server"}}}, None),
    ("CX001", "repo", ".codex/config.toml",
     'sandbox_mode = "danger-full-access"', 'sandbox_mode = "workspace-write"'),
    ("CX002", "repo", ".codex/config.toml",
     'approval_policy = "never"', 'approval_policy = "on-request"'),
    ("CX003", "repo", ".codex/config.toml",
     '[shell_environment_policy]\ninherit = "all"',
     '[shell_environment_policy]\ninherit = "core"'),
    ("CX004", "repo", ".codex/config.toml",
     '[mcp_servers.demo]\ndefault_tools_approval_mode = "approve"',
     '[mcp_servers.demo]\ndefault_tools_approval_mode = "prompt"'),
    ("CX005", "repo", ".codex/config.toml",
     '[sandbox_workspace_write]\nnetwork_access = true',
     '[sandbox_workspace_write]\nnetwork_access = false'),
    ("CX006", "user", ".codex/config.toml",
     '[projects."/"]\ntrust_level = "trusted"',
     '[projects."/synthetic/project"]\ntrust_level = "trusted"'),
    ("CX007", "repo", ".codex/config.toml", "", None),
    ("CU001", "repo", ".cursor/sandbox.json",
     {"readBoundary": "workspace", "additionalReadPaths": ["/synthetic/path"]}, None),
    ("CU002", "repo", ".cursor/permissions.json", {}, None),
    ("SEC001", "repo", ".claude/settings.json",
     {"nested": [{"value": "ghp_SyntheticFixtureOnly123456789"}]},
     {"nested": [{"value": "${TOKEN_FROM_ENV}"}]}),
    ("GEN001", "repo", ".mcp.json", "symlink", {}),
    ("GEN002", "repo", ".claude/settings.json", "{broken", {}),
]


@pytest.mark.parametrize("rule_id,scope,name,positive,negative", CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize("trigger", [True, False], ids=["positive", "negative"])
def test_rule(rule_id, scope, name, positive, negative, trigger, repo, fake_home, tmp_path):
    data = positive if trigger else negative
    root = repo if scope == "repo" else fake_home
    if rule_id == "CC008":
        write(repo, ".env.synthetic", "SYNTHETIC_ONLY=yes")
    if rule_id == "GEN001" and trigger:
        target = write(tmp_path, "outside-config.json", {"mcpServers": {}})
        (root / name).symlink_to(target)
    elif data is not None:
        write(root, name, data)
    findings = rules.scan(repo, include_home=scope == "user")["findings"]
    matching = [f for f in findings if f["rule_id"] == rule_id]
    assert bool(matching) is trigger
    for finding in matching:
        assert finding["severity"] == rules.RULES[rule_id][0]
        assert finding["file"] == str(root / name) or rule_id == "CC008"
        assert isinstance(finding["path"], str)
        assert finding["why"] and finding["fix"] and finding["source"].startswith("https://")


def test_every_rule_has_a_fixture():
    assert {case[0] for case in CASES} == rules.RULES.keys()


@pytest.mark.parametrize("entry", ["Bash", "Bash(*)"] + [
    f"Bash({shell}{wildcard})"
    for shell in "sh bash zsh python python3 node perl ruby eval xargs env sudo curl wget".split()
    for wildcard in (":*", " *")
])
def test_cc003_all_broad_permissions(entry, repo):
    write(repo, ".claude/settings.json", {"permissions": {"allow": [entry]}})
    assert any(f["rule_id"] == "CC003" for f in rules.scan(repo)["findings"])


@pytest.mark.parametrize("entry", ["Bash(pytest:*)", "Bash(python test.py)", "Read(*)", "Bashful"])
def test_cc003_specific_permissions(entry, repo):
    write(repo, ".claude/settings.json", {"permissions": {"allow": [entry]}})
    assert not rules.scan(repo)["findings"]


@pytest.mark.parametrize("key", ["HTTPS_PROXY", "HTTP_PROXY", "NODE_OPTIONS", "CUSTOM_BASE_URL"])
def test_cc006_all_redirect_keys(key, repo):
    write(repo, ".claude/settings.json", {"env": {key: "synthetic-value"}})
    assert any(f["rule_id"] == "CC006" for f in rules.scan(repo)["findings"])


@pytest.mark.parametrize("mode", ["auto", "bypassPermissions"])
def test_cc002_repo_modes(mode, repo):
    write(repo, ".claude/settings.local.json", {"permissions": {"defaultMode": mode}})
    assert any(f["rule_id"] == "CC002" for f in rules.scan(repo)["findings"])


@pytest.mark.parametrize("deny", ["Read(./.env*)", "Read(.env)"])
def test_cc008_denial_in_either_repo_settings(deny, repo):
    write(repo, ".env.synthetic", "synthetic")
    write(repo, ".claude/settings.local.json", {"permissions": {"deny": [deny]}})
    assert not rules.scan(repo)["findings"]


@pytest.mark.parametrize("command,args,unpinned", [
    ("npx", ["example"], True),
    ("npx", ["-y", "@scope/example"], True),
    ("npx", ["example@1.2.3"], False),
    ("npx", ["@scope/example@1.2.3"], False),
    ("npx", ["example@latest"], True),
    ("npx", ["--package", "example", "binary"], True),
    ("npx", ["--package=example@1.2.3", "binary"], False),
    ("uvx", ["example"], True),
    ("uvx", ["example==1.2.3"], False),
    ("uvx", ["--from", "example==1.2.3", "binary"], False),
    ("uvx", ["--from", "example", "binary"], True),
    ("uvx", ["example@1.2.3"], False),
    ("pipx", ["run", "example"], True),
    ("pipx", ["run", "--spec", "example==1.2.3", "binary"], False),
    ("pipx", ["run", "example@1.2.3"], False),
    ("pipx", ["install", "example"], False),
    ("bunx", ["example"], True),
    ("bunx", ["example@1.2.3"], False),
    ("pnpm", ["dlx", "example"], True),
    ("pnpm", ["dlx", "example@1.2.3"], False),
    ("/synthetic/bin/npx", ["example"], True),
    ("node", ["example"], False),
])
def test_launcher_versions(command, args, unpinned):
    assert rules.launcher_unpinned(command, args) is unpinned


@pytest.mark.parametrize("url,insecure", [
    ("http://example.invalid/mcp", True),
    ("http://localhost.evil.invalid", True),
    ("http://localhost:9000", False),
    ("http://127.0.0.1:9000", False),
    ("http://[::1]:9000", False),
    ("https://example.invalid/mcp", False),
])
def test_mcp003_local_exceptions(url, insecure):
    assert rules.insecure_remote(url) is insecure


@pytest.mark.parametrize("token", [
    "sk-ant-SyntheticOnly123", "sk-proj-SyntheticOnly123", "ghp_SyntheticOnly123",
    "gho_SyntheticOnly123", "github_pat_SyntheticOnly123", "glpat-SyntheticOnly123",
    "xoxb-SyntheticOnly123", "xoxp-SyntheticOnly123", "AKIA" + "A" * 16,
    "AIza" + "a" * 35,
])
def test_sec001_every_prefix(token, repo):
    write(repo, ".claude/settings.json", {"nested": ["Bearer " + token]})
    findings = rules.scan(repo)["findings"]
    assert [f["rule_id"] for f in findings] == ["SEC001"]
    assert token not in json.dumps(findings)


@pytest.mark.parametrize("key", [
    "TOKEN", "api_key", "secret", "password", "Authorization", "ordinary",
])
@pytest.mark.parametrize("field", ["env", "headers", "http_headers"])
def test_mcp001_fields_and_sec001_dedup(key, field, repo):
    write(repo, ".mcp.json", {"mcpServers": {"demo": {field: {key: "ghp_SyntheticOnly123"}}}})
    ids = [f["rule_id"] for f in rules.scan(repo)["findings"]]
    assert ids.count("MCP001") == 1
    assert "SEC001" not in ids


@pytest.mark.parametrize("name", [".mcp.json", ".cursor/mcp.json"])
def test_mcp004_lists_each_server_and_launch(name, repo):
    write(repo, name, {"mcpServers": {
        "local": {"command": "synthetic-server", "args": ["--synthetic"]},
        "remote": {"url": "https://example.invalid/mcp"},
    }})
    found = [f for f in rules.scan(repo)["findings"] if f["rule_id"] == "MCP004"]
    assert len(found) == 2
    details = " ".join(f["details"] for f in found)
    assert all(value in details for value in ("local", "remote", "synthetic-server", "--synthetic",
                                            "https://example.invalid/mcp"))


def test_codex_per_tool_approval(repo):
    write(repo, ".codex/config.toml", '[mcp_servers.demo.tools.search]\napproval_mode = "approve"')
    finding = next(f for f in rules.scan(repo)["findings"] if f["rule_id"] == "CX004")
    assert finding["path"] == "mcp_servers.demo.tools.search.approval_mode"


def test_cx006_uses_fake_home(repo, fake_home):
    write(fake_home, ".codex/config.toml", f'[projects.{json.dumps(str(fake_home))}]\n'
          'trust_level = "trusted"')
    assert any(f["rule_id"] == "CX006" for f in rules.scan(repo, True)["findings"])


def test_repo_only_rules_do_not_apply_to_home(repo, fake_home):
    write(fake_home, ".claude/settings.json", {
        "hooks": {}, "apiKeyHelper": "synthetic-helper", "env": {"HTTPS_PROXY": "value"},
    })
    write(fake_home, ".codex/config.toml", "")
    write(fake_home, ".cursor/permissions.json", {})
    write(fake_home, ".cursor/sandbox.json", {})
    write(fake_home, ".cursor/mcp.json", {"mcpServers": {"demo": {"command": "server"}}})
    assert not rules.scan(repo, True)["findings"]


def test_user_claude_json_only_mcp_servers(repo, fake_home):
    write(fake_home, ".claude.json", {
        "ignored": "ghp_SyntheticIgnored123", "permissions": {"defaultMode": "bypassPermissions"},
        "mcpServers": {"global": {"env": {"TOKEN": "synthetic-global-secret"}}},
        "projects": {"/synthetic/project": {
            "ignored": "ghp_SyntheticAlsoIgnored123",
            "mcpServers": {"local": {"url": "http://example.invalid/mcp"}},
        }},
    })
    found = rules.scan(repo, True)["findings"]
    assert {f["rule_id"] for f in found} == {"MCP001", "MCP003"}
    assert any(f["path"] == "/projects/~1synthetic~1project/mcpServers/local/url" for f in found)


def test_codex_mcp_rules(repo):
    write(repo, ".codex/config.toml", '[mcp_servers.demo]\ncommand = "uvx"\nargs = ["demo"]\n'
          'url = "http://example.invalid"\n[mcp_servers.demo.http_headers]\n'
          'Authorization = "synthetic-codex-secret"')
    found = rules.scan(repo)["findings"]
    assert {f["rule_id"] for f in found} == {"CX007", "MCP001", "MCP002", "MCP003"}
    assert {f["source"] for f in found if f["rule_id"] != "CX007"} == {rules.CX}
    assert next(f for f in found if f["rule_id"] == "CX007")["source"] == rules.CX_CFG


def test_pointer_escaping():
    doc = rules.discover.Document("example", ".mcp.json", "repo", {})
    assert doc.pointer(("mcpServers", "a/b~c")) == "/mcpServers/a~1b~0c"
    doc.name = ".codex/config.toml"
    assert doc.pointer(("projects", "/synthetic/home", "trust_level")) == (
        'projects."/synthetic/home".trust_level'
    )


def test_home_not_consulted_without_flag(repo, monkeypatch):
    def forbidden_home(cls):
        raise AssertionError("home scope must be explicit")
    monkeypatch.setattr(Path, "home", classmethod(forbidden_home))
    assert rules.scan(repo) == {"findings": [], "notes": []}
