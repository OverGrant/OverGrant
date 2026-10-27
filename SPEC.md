# overgrant v0.1 spec

Every rule is tied to a config key verified from vendor docs on 2026-10-26. A rule never ships
on a guessed key. Sources:
- [CC-SET] https://code.claude.com/docs/en/settings
- [CC-REF] https://code.claude.com/docs/en/settings-reference
- [CC-PERM] https://code.claude.com/docs/en/permissions (includes "What runs before you trust a folder")
- [CC-HOOKS] https://code.claude.com/docs/en/hooks
- [CC-MCP] https://code.claude.com/docs/en/mcp
- [CX] https://github.com/openai/codex, `codex-rs/core/config.schema.json`
- [CX-CFG] https://learn.chatgpt.com/docs/config-file/config-advanced ("loads project-scoped config files only when the project is trusted"; verified 2026-10-27)
- [CC-MODES] https://code.claude.com/docs/en/permission-modes
- [CU-MCP] https://cursor.com/docs/context/mcp
- [CU-RUN] https://cursor.com/docs/agent/security/run-modes (where the `permissions.json` and `sandbox.json` files are documented)

## CLI
`overgrant scan [PATH] [--home] [--format text|json|sarif] [--fail-on low|medium|high|critical]`
- PATH defaults to the current directory. It is the **repo scope**: files a cloned repo can ship.
- `--home` adds the **user scope**: `~/.claude/settings.json`, `~/.claude.json`,
  `~/.codex/config.toml`, `~/.cursor/mcp.json`, `~/.cursor/permissions.json`,
  `~/.cursor/sandbox.json`.
- Exit code: 0 for clean, 1 when a finding is at or above `--fail-on` (default `high`), 2 for a
  usage error.

## Files read
| Tool | Repo scope | User scope | Format |
|---|---|---|---|
| Claude Code | `.claude/settings.json`, `.claude/settings.local.json`, `.mcp.json` | `~/.claude/settings.json`; `~/.claude.json` (only `mcpServers` and `projects.*.mcpServers`) | JSON |
| Codex | `.codex/config.toml` (loaded only once the project is trusted [CX-CFG]) | `~/.codex/config.toml` | TOML (`tomllib`) |
| Cursor | `.cursor/mcp.json`, `.cursor/permissions.json`, `.cursor/sandbox.json` | the same names under `~/.cursor/` | JSON |

## Safety of the scanner itself (scanned files are untrusted)
- Never execute, import or fetch anything named in a config. No network.
- Never print a secret. Print it redacted as its first 4 characters, `…`, and its length.
- Never echo file contents in parse errors. Say only "file X is not valid JSON/TOML (line N)".
- In repo scope, don't follow symlinks. Report a symlinked config file as a finding instead.
- Cap each file at 5 MB and skip larger files with a note.

## Rules
Severities: C (critical), H (high), M (medium), L (low).

### Claude Code
| ID | Sev | Condition | Source |
|---|---|---|---|
| CC001 | C | `permissions.defaultMode` is `bypassPermissions` in user scope | CC-PERM |
| CC002 | L | `defaultMode` is `bypassPermissions` or `auto` in repo scope. Project files cannot enable these modes (verified 2026-10-27), but it signals intent | CC-MODES |
| CC003 | H | A `permissions.allow` entry gives a bare `Bash` or `Bash(*)`, or a shell or interpreter with a wildcard. The list is sh, bash, zsh, python, python3, node, perl, ruby, eval, xargs, env, sudo, curl, wget, followed by `:*` or ` *` | CC-PERM |
| CC004 | H | A repo `.claude/settings*.json` defines `hooks`. In `-p` runs and in parent-trusted folders they run before trust | CC-PERM, CC-HOOKS |
| CC005 | H | A repo settings file sets `apiKeyHelper`, which runs before trust in the same cases | CC-REF, CC-PERM |
| CC006 | H | A repo `env` sets a variable ending in `_BASE_URL`, or one of `HTTPS_PROXY`, `HTTP_PROXY`, `NODE_OPTIONS`. These can redirect API traffic or keys | CC-REF |
| CC007 | M | `enableAllProjectMcpServers: true` in user scope: every repo's `.mcp.json` servers are approved | CC-REF, CC-MCP |
| CC008 | L | The repo has a `.env*` file and no `permissions.deny` entry matching `Read(./.env*)` or `Read(.env)` | CC-PERM |

### MCP servers (Claude `.mcp.json` / `~/.claude.json`, Cursor `mcp.json`, Codex `[mcp_servers.*]`)
| ID | Sev | Condition | Source |
|---|---|---|---|
| MCP001 | H | A literal secret is in `env`, `headers` or `http_headers`. That is a key matching `TOKEN`, `KEY`, `SECRET`, `PASSWORD` or `AUTH` with a value that isn't `${...}` interpolation, or any value matching a known token prefix (see SEC001) | CC-MCP, CU-MCP, CX |
| MCP002 | M | Unpinned package launch: `npx` with a package arg that has no `@<version>`, `uvx` or `pipx run` with no `==<version>` or `@<version>`, or `bunx`/`pnpm dlx` unpinned. A later release can change the code, which is the rug-pull pattern | CC-MCP |
| MCP003 | M | A remote `url` uses `http://` and isn't localhost, 127.0.0.1 or ::1 | CC-MCP |
| MCP004 | H | The repo ships `.mcp.json` or `.cursor/mcp.json`. List each server and its command or URL. Claude loads them without a prompt in `-p`, SDK and cloud sessions | CC-MCP |

### Codex
| ID | Sev | Condition | Source |
|---|---|---|---|
| CX001 | C | `sandbox_mode = "danger-full-access"` | CX |
| CX002 | M | `approval_policy = "never"` (it becomes CX001's critical when combined with that) | CX |
| CX003 | H | `shell_environment_policy.inherit = "all"`: the agent's shell sees every environment variable, keys included | CX |
| CX004 | M | `mcp_servers.<n>.default_tools_approval_mode = "approve"`, or a per-tool `approval_mode = "approve"`: tool calls are auto-approved | CX |
| CX005 | M | `sandbox_workspace_write.network_access = true` | CX |
| CX006 | L | `projects."<path>".trust_level = "trusted"` where the path is `/` or the home directory | CX |
| CX007 | H | The repo ships `.codex/config.toml`. Codex loads it once the project is trusted, so run CX001–CX005 on it as repo-supplied | CX-CFG |

### Cursor
| ID | Sev | Condition | Source |
|---|---|---|---|
| CU001 | H | The repo ships `.cursor/sandbox.json` (the project file takes priority). Show `readBoundary` and `additionalReadPaths` | CU-RUN |
| CU002 | M | The repo ships `.cursor/permissions.json` (merged with the user file) | CU-RUN |

### Everywhere
| ID | Sev | Condition |
|---|---|---|
| SEC001 | H | A value anywhere in a scanned file matches a known token prefix: `sk-ant-`, `sk-proj-`, `ghp_`, `gho_`, `github_pat_`, `glpat-`, `xoxb-`, `xoxp-`, `AKIA[0-9A-Z]{16}`, `AIza[0-9A-Za-z_-]{35}`. Deduplicate with MCP001 |
| GEN001 | M | A config file in repo scope is a symlink |

Each finding has: rule ID, severity, file, a JSON-pointer or TOML key path, a one-sentence
"why", the exact fix, and the source URL.
