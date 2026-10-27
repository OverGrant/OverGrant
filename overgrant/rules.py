"""Deterministic rules over parsed data. No config value is executable."""

import json
import re
import shlex
from pathlib import Path
from urllib.parse import urlsplit

from . import discover

CC_SET = "https://code.claude.com/docs/en/settings"
CC_REF = "https://code.claude.com/docs/en/settings-reference"
CC_PERM = "https://code.claude.com/docs/en/permissions"
CC_MCP = "https://code.claude.com/docs/en/mcp"
CX = "https://github.com/openai/codex/blob/main/codex-rs/core/config.schema.json"
CX_CFG = "https://learn.chatgpt.com/docs/config-file/config-advanced"
CC_MODES = "https://code.claude.com/docs/en/permission-modes"
CU_MCP = "https://cursor.com/docs/context/mcp"
CU_RUN = "https://cursor.com/docs/agent/security/run-modes"

# ID -> severity, why (one sentence), exact remediation, authoritative source.
RULES = {
    "CC001": ("critical", "User settings bypass permission checks.",
              'Set permissions.defaultMode to "default" in user settings.', CC_PERM),
    "CC002": ("low", "Project settings cannot enable this mode, but the request signals intent.",
              "Remove permissions.defaultMode from repository settings.", CC_MODES),
    "CC003": ("high", "A broad shell or interpreter permission allows arbitrary commands.",
              "Remove this permissions.allow entry and allow only specific commands.", CC_PERM),
    "CC004": ("high", "Repository hooks can run before trust in headless or parent-trusted use.",
              "Remove hooks from repository settings; review commands before adding user hooks.",
              "https://code.claude.com/docs/en/hooks"),
    "CC005": ("high", "A repository API key helper can execute before trust.",
              "Remove apiKeyHelper from repository settings.", CC_REF),
    "CC006": ("high", "Repository environment settings can redirect traffic or load code.",
              "Remove this env entry from repository settings.", CC_REF),
    "CC007": ("medium", "User settings approve every repository's project MCP servers.",
              "Set enableAllProjectMcpServers to false and approve servers individually.", CC_REF),
    "CC008": ("low", "Repository dotenv files lack an explicit Claude read denial.",
              'Add "Read(./.env*)" to permissions.deny in .claude/settings.json.', CC_PERM),
    "MCP001": ("high", "An MCP server configuration contains a literal secret.",
               "Remove the literal, rotate it, and use supported environment interpolation "
               "or an external secret provider.", CC_MCP),
    "MCP002": ("medium", "An unpinned package launcher can run changed code on a later release.",
               "Pin the launched package to an explicit version using package@VERSION "
               "for npx/bunx/pnpm dlx or package==VERSION for uvx/pipx run.", CC_MCP),
    "MCP003": ("medium", "An MCP server uses unencrypted HTTP outside the local host.",
               "Change the server url to https:// with a verified TLS endpoint.", CC_MCP),
    "MCP004": ("high", "Repository MCP servers can be loaded by unattended agent sessions.",
               "Remove this server from the repository MCP file; review it before adding "
               "it to user configuration.", CC_MCP),
    "CX001": ("critical", "The Codex sandbox grants full system access.",
              'Set sandbox_mode = "workspace-write" or "read-only".', CX),
    "CX002": ("medium", "Codex never requests approval for commands.",
              'Set approval_policy = "on-request".', CX),
    "CX003": ("high", "The Codex shell inherits all environment variables, including secrets.",
              'Set shell_environment_policy.inherit = "core" or "none".', CX),
    "CX004": ("medium", "Codex MCP tool calls are automatically approved.",
              'Remove this "approve" setting and require approval for the affected tools.', CX),
    "CX005": ("medium", "The Codex workspace sandbox allows network access.",
              "Set sandbox_workspace_write.network_access = false.", CX),
    "CX006": ("low", "A Codex trust entry covers the filesystem root or home directory.",
              "Remove this projects trust entry and trust only individual reviewed repositories.",
              CX),
    "CX007": ("high", "Once the project is trusted, Codex loads this repository-supplied config.",
              "Remove .codex/config.toml from the repository and review needed user settings.",
              CX_CFG),
    "CU001": ("high", "Repository Cursor sandbox settings take priority over user settings.",
              "Remove .cursor/sandbox.json and configure reviewed boundaries in user settings.",
              CU_RUN),
    "CU002": ("medium", "Repository Cursor permissions are merged with user permissions.",
              "Remove .cursor/permissions.json and configure reviewed user permissions.",
              CU_RUN),
    "SEC001": ("high", "A configuration value contains a known secret token prefix.",
               "Remove the literal token, rotate it, and load it from an external secret provider.",
               "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/"
               "removing-sensitive-data-from-a-repository"),
    "GEN001": ("medium", "A repository config path is a symlink and was not followed.",
               "Remove the symlink and use a reviewed regular config file inside the repository.",
               "https://cwe.mitre.org/data/definitions/61.html"),
    "GEN002": ("high", "Unreadable agent config may contain pre-trust execution settings.",
               "Remove the repository settings file or make it readable, valid JSON "
               "within the size limit, then scan it again.", CC_PERM),
}
SEVERITY = {"low": 0, "medium": 1, "high": 2, "critical": 3}
TOKEN = re.compile(
    r"(?:(?:sk-ant-|sk-proj-|ghp_|gho_|github_pat_|glpat-|xoxb-|xoxp-)|"
    r"AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35})[^\s\"'<>]*"
)
SECRET_SEGMENTS = {"TOKEN", "KEY", "SECRET", "PASSWORD", "AUTH", "APIKEY"}
INTERPOLATION = re.compile(r"\$\{(?:env:)?[A-Za-z_][A-Za-z0-9_]*(?::-(.*))?\}", re.S)
BROAD_BASH = re.compile(
    r"Bash\((?:[^()\s]*/)?(?:sh|bash|zsh|(?:python|node|perl|ruby)(?:\d+(?:\.\d+)*)?"
    r"|eval|xargs|env|sudo|curl|wget)(?: -c)?(?::\*| \*)\)"
)


def mapping(value):
    return value if isinstance(value, dict) else {}


def sequence(value):
    return value if isinstance(value, list) else []


def leaves(value, path=()):
    """Iterate leaves without trusting the shape or nesting depth of a config."""
    stack = [(path, value)]
    while stack:
        current, item = stack.pop()
        if isinstance(item, dict):
            stack.extend(((*current, key), child) for key, child in reversed(item.items()))
        elif isinstance(item, list):
            stack.extend(((*current, index), child)
                         for index, child in reversed(list(enumerate(item))))
        else:
            yield current, item


def redact_secret(value: str) -> str:
    if len(value) <= 8:
        return f"****(len {len(value)})"
    return f"{value[:4]}… (length {len(value)})"


class Redactor:
    def __init__(self):
        self.secrets = set()
        self.pattern = None

    def redact(self, value: str) -> str:
        if value in self.secrets:
            return redact_secret(value)
        # One pass avoids reprocessing a redaction when secrets share prefixes.
        if self.pattern is None:
            alternatives = sorted((re.escape(s) for s in self.secrets if len(s) >= 8),
                                  key=len, reverse=True)
            self.pattern = (re.compile(TOKEN.pattern + "|" + "|".join(alternatives))
                            if alternatives else TOKEN)
        return self.pattern.sub(lambda match: redact_secret(match[0]), value)

    def safe_details(self, value):
        result = [None]
        stack = [(result, 0, value)]
        while stack:
            parent, key, item = stack.pop()
            if isinstance(item, dict):
                parent[key] = {}
                stack.extend((parent[key], self.redact(str(k)), child) for k, child in item.items())
            elif isinstance(item, list):
                parent[key] = [None] * len(item)
                stack.extend((parent[key], index, child) for index, child in enumerate(item))
            else:
                parent[key] = self.redact(item) if isinstance(item, str) else item
        return result[0]


def server_groups(document):
    data = document.data
    if document.name == ".codex/config.toml":
        yield ("mcp_servers",), mapping(data.get("mcp_servers"))
    elif document.name in (".mcp.json", ".cursor/mcp.json", ".claude.json"):
        yield ("mcpServers",), mapping(data.get("mcpServers"))
        if document.name == ".claude.json":
            for name, project in mapping(data.get("projects")).items():
                yield ("projects", name, "mcpServers"), mapping(mapping(project).get("mcpServers"))


def literal_secret(key, value):
    if not isinstance(value, (str, int, float)) or isinstance(value, bool) or value == "":
        return False
    text = str(value)
    segments = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(key))
    segments = re.findall(r"[A-Z0-9]+", segments.upper())
    secret_key = bool(segments) and (
        segments[-1] in SECRET_SEGMENTS or segments[-1] == "AUTHORIZATION"
    ) and segments[-2:] != ["NO", "AUTH"]
    # Only a complete interpolation without a literal fallback is safe. Nested
    # interpolation defaults are inspected too; each iteration shortens the text.
    fallback = text
    while match := INTERPOLATION.fullmatch(fallback):
        fallback = match[1]
        if not fallback:
            return bool(TOKEN.search(text))
    return bool(TOKEN.search(text)) or secret_key


def _basename(command):
    return re.sub(r"\.(?:exe|cmd)$", "", command.replace("\\", "/").rsplit("/", 1)[-1],
                  flags=re.I)


def _launch_words(command, args):
    """Unwrap documented launchers using string parsing only, never a shell."""
    if not isinstance(command, str):
        return []
    try:
        words = shlex.split(command)
        words += [arg for arg in sequence(args) if isinstance(arg, str)]
        while words:
            launcher = _basename(words[0]).lower()
            if launcher in ("cmd", "sh", "bash") and len(words) >= 3:
                if words[1].lower() != ("/c" if launcher == "cmd" else "-c"):
                    break
                script = " ".join(words[2:]) if launcher == "cmd" else words[2]
                words = shlex.split(script)
            elif launcher == "env":
                words.pop(0)
                while words:
                    if words[0] == "--":
                        words.pop(0)
                        break
                    if words[0] in ("-u", "--unset", "-C", "--chdir"):
                        del words[:2]
                    elif words[0].startswith("-") or "=" in words[0]:
                        words.pop(0)
                    else:
                        break
            else:
                break
        return words
    except ValueError:
        return []


def _launcher_packages(command, args):
    words = _launch_words(command, args)
    if not words:
        return []
    launcher = _basename(words.pop(0)).lower()
    subcommands = {"pnpm": ["dlx"], "pipx": ["run"], "npm": ["exec"],
                   "uv": ["tool", "run"], "yarn": ["dlx"]}
    if launcher in subcommands:
        prefix = subcommands[launcher]
        if words[:len(prefix)] != prefix:
            return []
        del words[:len(prefix)]
    elif launcher not in ("npx", "uvx", "bunx"):
        return []
    # Options consuming a separate value, including package overrides and indexes.
    value_options = {
        "--package", "-p", "--from", "--spec", "--index", "--index-url", "-i",
        "--extra-index-url", "--python", "--python-version", "--cache-dir", "--registry", "--with",
    }
    packages, index, overrides_command = [], 0, False
    while index < len(words):
        word = words[index]
        if word == "--":
            if index + 1 < len(words) and not overrides_command:
                packages.append(words[index + 1])
            break
        option, _, attached = word.partition("=")
        if option in value_options:
            argument = attached or (words[index + 1] if index + 1 < len(words) else "")
            if option in ("--package", "-p", "--from", "--spec", "--with") and argument:
                packages.append(argument)
                overrides_command |= option != "--with"
            index += 1 if attached else 2
            continue
        if word.startswith("-"):
            index += 1
            continue
        if not overrides_command:
            packages.append(word)
        break  # remaining words are arguments to the launched program
    return packages


def launcher_unpinned(command, args):
    """Inspect all launched packages, including supplemental uv dependencies."""
    for package in _launcher_packages(command, args):
        # A scope's leading @ is not a version separator.
        body = package[1:] if package.startswith("@") else package
        marker = re.search(r"(?:==|@)(.+)$", body)
        if not marker or not re.fullmatch(r"v?[0-9][A-Za-z0-9.+_-]*", marker[1]):
            return True
    return False


def launch_details(server):
    """Summarize a launch without echoing a command line or URL authentication."""
    description = {}
    command, args = server.get("command"), server.get("args")
    words = _launch_words(command, args)
    # Inspect the original arguments too: shell wrappers may hide a complete
    # command string in one argument, which must never be echoed as-is.
    original_args = [arg for arg in sequence(args) if isinstance(arg, str)]
    sensitive = set()
    for arguments in (original_args, words[1:]):
        previous = ""
        for arg in arguments:
            if (previous.startswith("-") or previous.lower() == "/c" or "=" in arg or
                    re.search(r"[A-Za-z0-9_+/=.-]{12,}", arg)):
                sensitive.add(arg)
            previous = arg
    if words:
        description["command"] = _basename(words[0])
        packages = _launcher_packages(command, args)
        if packages:
            description["packages"] = [redact_secret(p) if p in sensitive else p for p in packages]
    if isinstance(args, list):
        description["args"] = [redact_secret(arg) if arg in sensitive else arg
                               for arg in original_args]
    url = server.get("url")
    if isinstance(url, str):
        try:
            parsed = urlsplit(url)
            if parsed.scheme and parsed.hostname:
                description["url"] = (f"{parsed.scheme}://"
                                      f"{parsed.netloc.rsplit('@', 1)[-1]}{parsed.path}")
            else:
                description["url"] = "Invalid URL; omitted."
        except ValueError:
            description["url"] = "Invalid URL; omitted."
    return description


def insecure_remote(value):
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
        return parsed.scheme.lower() == "http" and parsed.hostname not in (
            "localhost", "127.0.0.1", "::1",
        )
    except ValueError:
        return value.lower().startswith("http://")


def scan(root: Path, include_home=False):
    home = Path.home().resolve() if include_home else None
    documents, notes, symlinks, env_files = discover.load(root, include_home, home=home)
    findings, redactor = [], Redactor()
    locations = []

    def add(rule_id, document, parts=(), details=""):
        severity, why, fix, source = RULES[rule_id]
        if rule_id.startswith("MCP"):
            if document.name.startswith(".cursor/"):
                source = CU_MCP
            elif document.name == ".codex/config.toml":
                source = CX
        findings.append({
            "rule_id": rule_id, "severity": severity, "file": document.file,
            "path": document.pointer(parts), "why": why, "fix": fix,
            "source": source, "details": details,
        })
        locations.append((document, parts))

    for file in symlinks:
        add("GEN001", discover.Document(file, "", "repo", {}))

    for document in documents:
        data, repo = document.data, document.scope == "repo"
        covered = set()
        for base, servers in server_groups(document):
            if repo and document.name in (".mcp.json", ".cursor/mcp.json") and not servers:
                add("MCP004", document, base, "No configured servers.")
            for name, raw_server in servers.items():
                server = mapping(raw_server)
                path = (*base, name)
                for field in ("env", "headers", "http_headers"):
                    for relative, value in leaves(mapping(server.get(field))):
                        if relative and literal_secret(relative[-1], value):
                            location = (*path, field, *relative)
                            covered.add(location)
                            redactor.secrets.add(str(value))
                            add("MCP001", document, location, str(value))
                if launcher_unpinned(server.get("command"), server.get("args")):
                    add("MCP002", document, (*path, "command"))
                if insecure_remote(server.get("url")):
                    add("MCP003", document, (*path, "url"))
                if repo and document.name in (".mcp.json", ".cursor/mcp.json"):
                    add("MCP004", document, path, {"server": name, **launch_details(server)})
        for path, value in leaves(data):
            if isinstance(value, str):
                tokens = [match[0] for match in TOKEN.finditer(value)]
                redactor.secrets.update(tokens)
                if tokens and path not in covered:
                    add("SEC001", document, path, ", ".join(tokens))

        if document.name in (".claude/settings.json", ".claude/settings.local.json"):
            if repo and document.unreadable:
                add("GEN002", document)
            permissions = mapping(data.get("permissions"))
            mode = permissions.get("defaultMode")
            if repo and mode in ("bypassPermissions", "auto"):
                add("CC002", document, ("permissions", "defaultMode"))
            elif not repo and mode == "bypassPermissions":
                add("CC001", document, ("permissions", "defaultMode"))
            for index, entry in enumerate(sequence(permissions.get("allow"))):
                if isinstance(entry, str) and (
                    entry in ("Bash", "Bash(*)") or BROAD_BASH.fullmatch(entry)
                ):
                    add("CC003", document, ("permissions", "allow", index))
            if repo:
                for key, rule in (("hooks", "CC004"), ("apiKeyHelper", "CC005")):
                    if key in data:
                        add(rule, document, (key,))
                for key in mapping(data.get("env")):
                    if key.endswith("_BASE_URL") or key in (
                        "HTTPS_PROXY", "HTTP_PROXY", "NODE_OPTIONS",
                    ):
                        add("CC006", document, ("env", key))
            elif data.get("enableAllProjectMcpServers") is True:
                add("CC007", document, ("enableAllProjectMcpServers",))

        if document.name == ".codex/config.toml":
            for key, value, rule in (
                ("sandbox_mode", "danger-full-access", "CX001"),
                ("approval_policy", "never", "CX002"),
            ):
                if data.get(key) == value:
                    add(rule, document, (key,))
            if mapping(data.get("shell_environment_policy")).get("inherit") == "all":
                add("CX003", document, ("shell_environment_policy", "inherit"))
            for name, raw_server in mapping(data.get("mcp_servers")).items():
                server = mapping(raw_server)
                if server.get("default_tools_approval_mode") == "approve":
                    add("CX004", document, ("mcp_servers", name, "default_tools_approval_mode"))
                for tool, settings in mapping(server.get("tools")).items():
                    if mapping(settings).get("approval_mode") == "approve":
                        add("CX004", document,
                            ("mcp_servers", name, "tools", tool, "approval_mode"))
            if mapping(data.get("sandbox_workspace_write")).get("network_access") is True:
                add("CX005", document, ("sandbox_workspace_write", "network_access"))
            # Path.home is evaluated only when project trust entries actually exist.
            for project, settings in mapping(data.get("projects")).items():
                if home is None:
                    home = Path.home().resolve()
                if (mapping(settings).get("trust_level") == "trusted" and
                        Path(project) in (Path("/"), home)):
                    add("CX006", document, ("projects", project, "trust_level"))
            if repo:
                add("CX007", document)

        if repo and document.name == ".cursor/sandbox.json":
            shown = {key: data.get(key) for key in ("readBoundary", "additionalReadPaths")}
            add("CU001", document, details=shown)
        if repo and document.name == ".cursor/permissions.json":
            add("CU002", document)

    denied = any(
        entry in ("Read(./.env*)", "Read(.env)")
        for doc in documents if doc.scope == "repo" and doc.name.startswith(".claude/settings")
        for entry in sequence(mapping(doc.data.get("permissions")).get("deny"))
    )
    if not denied:
        for file in env_files:
            add("CC008", discover.Document(file, "", "repo", {}))
    for finding, (document, parts) in zip(findings, locations, strict=True):
        finding["file"] = redactor.redact(finding["file"])
        # Redact raw key names before JSON-pointer escaping or TOML quoting.
        finding["path"] = document.pointer(tuple(redactor.redact(str(part)) for part in parts))
        details = redactor.safe_details(finding["details"])
        try:
            finding["details"] = (json.dumps(details, ensure_ascii=False)
                                  if isinstance(details, dict) else details)
        except RecursionError:
            finding["details"] = "Details exceed the supported nesting depth; omitted."
    findings.sort(key=lambda f: (-SEVERITY[f["severity"]], f["file"], f["path"], f["rule_id"]))
    return {"findings": findings, "notes": [redactor.redact(note) for note in notes]}
