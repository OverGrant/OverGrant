# overgrant v0.1

Find what your AI coding agents were granted that they should not have.

Scan local Claude Code, Codex, Cursor, and MCP configuration for risky settings.
Python 3.12+, standard library only at runtime. No account or network is needed.

## 30-second quickstart

Run it without installing (needs [uv](https://docs.astral.sh/uv/)):

```sh
uvx overgrant scan .            # this repo
uvx overgrant scan . --home     # plus your user config
```

Or install it: `pipx install overgrant`, then `overgrant scan . --home`.
From a source checkout: `python3.12 -m overgrant.cli scan . --format sarif > report.sarif`.

An installed package also provides `overgrant scan`. PATH defaults to the current
directory. `--home` explicitly adds user configuration. `--format` accepts `text`
(default), `json`, or SARIF 2.1.0 (`sarif`). Exit status is 0 below the threshold,
1 for a finding at or above `--fail-on` (`high` by default), and 2 for invalid
usage or an inaccessible repository directory. Thresholds: low, medium, high,
critical. Parse errors, unreadable files, and oversized files appear as notes;
they do not count as findings or change the exit status, so inspect notes before
treating a report as complete.

Repo scope reads only `.claude/settings.json`, `.claude/settings.local.json`,
`.mcp.json`, `.codex/config.toml`, `.cursor/mcp.json`, `.cursor/permissions.json`,
and `.cursor/sandbox.json`. Root `.env*` filenames are checked using metadata.
User scope adds `~/.claude/settings.json`, `~/.claude.json`,
`~/.codex/config.toml`, and those three Cursor files under `~/.cursor/`.
For `~/.claude.json`, only `mcpServers` and `projects.*.mcpServers` are scanned.

Each finding includes a rule ID, severity, file, JSON pointer or TOML key path,
one-sentence explanation, remediation, and source URL. MCP server commands/URLs
and Cursor sandbox boundaries are displayed with secrets redacted. SARIF maps
critical/high to `error`, medium to `warning`, low to `note`, preserving the
original severity and key path in result properties.

## Rules

| ID | Severity | Detects |
| --- | --- | --- |
| CC001 | critical | User `permissions.defaultMode = bypassPermissions` |
| CC002 | low | Repo `defaultMode` requests `bypassPermissions` or `auto` |
| CC003 | high | Bare Bash or broad shell/interpreter wildcard allow entries |
| CC004 | high | Repo hooks, which can run before trust in unattended/trusted-parent use |
| CC005 | high | Repo `apiKeyHelper` |
| CC006 | high | Repo `_BASE_URL`, proxy, or `NODE_OPTIONS` environment overrides |
| CC007 | medium | User `enableAllProjectMcpServers: true` |
| CC008 | low | Root `.env*` files without either documented Claude read denial |
| MCP001 | high | Literal secrets in MCP `env`, `headers`, or `http_headers` |
| MCP002 | medium | Unpinned npx, uvx, pipx run, bunx, or pnpm dlx packages |
| MCP003 | medium | Remote HTTP MCP URL, except localhost, 127.0.0.1, or ::1 |
| MCP004 | high | Repo `.mcp.json` or `.cursor/mcp.json` servers and their launches |
| CX001 | critical | Codex `sandbox_mode = "danger-full-access"` |
| CX002 | medium | Codex `approval_policy = "never"` |
| CX003 | high | Codex shell inherits all environment variables |
| CX004 | medium | Codex default or per-tool MCP auto-approval |
| CX005 | medium | Codex workspace sandbox network access |
| CX006 | low | Codex trusts `/` or the home directory |
| CX007 | high | Repo `.codex/config.toml`, loaded once the project is trusted |
| CU001 | high | Repo Cursor sandbox settings, including read boundaries/paths |
| CU002 | medium | Repo Cursor permissions |
| SEC001 | high | Known token prefixes anywhere in scoped config values; deduped with MCP001 |
| GEN001 | medium | Repo config path is a symlink |
| GEN002 | high | A repo `.claude/settings*.json` is too large, unreadable or invalid, so it can't be checked (fails closed) |

Rule definitions and vendor references are in [SPEC.md](SPEC.md). Detection is
static: it cannot prove that a token is valid, a command is safe, or an agent
will apply a setting in a particular session.

## What it never does

- Executes commands, hooks, helpers, imports, or package launchers from configs.
- Fetches URLs, makes network calls, installs packages, or contacts a service.
- Fixes files, changes permissions, writes reports itself, or modifies configs.
- Opens `.env*` contents or recursively searches a repository or home directory.
- Follows repo symlinks, including symlinked config directories.
- Reads more than 5 MB plus one size-check byte per config; larger files are
  skipped with a note (known oversized files are skipped before reading).
- Echoes malformed file contents or parser exception text.
- Prints literal detected secrets: output shows the first four characters,
  `…`, and the value's length. Unrecognized secrets outside MCP secret fields
  are beyond these v0.1 rules; review reports before sharing them.

## Development

The preinstalled development tools can run fully offline:

```sh
.venv/bin/pytest -q
.venv/bin/ruff check .
```

Fixtures are synthetic and created under pytest's `tmp_path`. Every test uses
a fake HOME and patched `Path.home`; tests never scan the operator's home.
