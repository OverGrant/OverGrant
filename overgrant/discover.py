"""Read only the documented configuration files, with bounded, inert reads."""

import json
import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path

MAX_BYTES = 5 * 1024 * 1024
HOME_CLAUDE_MAX_BYTES = 50 * 1024 * 1024
REPO_FILES = (
    ".claude/settings.json", ".claude/settings.local.json", ".mcp.json",
    ".codex/config.toml", ".cursor/mcp.json", ".cursor/permissions.json",
    ".cursor/sandbox.json",
)
HOME_FILES = (
    ".claude/settings.json", ".claude.json", ".codex/config.toml",
    ".cursor/mcp.json", ".cursor/permissions.json", ".cursor/sandbox.json",
)


@dataclass
class Document:
    file: str
    name: str
    scope: str
    data: dict
    unreadable: bool = False

    def pointer(self, parts=()):
        if self.name.endswith(".toml"):
            return ".".join(
                str(p) if re.fullmatch(r"[A-Za-z0-9_-]+", str(p)) else json.dumps(str(p))
                for p in parts
            )
        return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in parts)


class SymlinkConfig(Exception):
    """A repo config or one of its parent directories is a symlink."""


class TooLarge(Exception):
    """A file exceeds the scan budget."""


def _open_root(root: Path) -> int:
    # The user-selected root is the trust boundary. Only entries below it are
    # subject to no-follow checks; ancestors such as macOS /tmp may be links.
    return os.open(root, os.O_RDONLY | os.O_DIRECTORY)


def _repo_read(root_fd: int, name: str) -> bytes | None:
    """Use directory descriptors so a concurrent symlink swap cannot escape the repo."""
    directory = os.dup(root_fd)
    try:
        parts = name.split("/")
        for index, part in enumerate(parts):
            try:
                info = os.stat(part, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return None
            if stat.S_ISLNK(info.st_mode):
                raise SymlinkConfig
            final = index == len(parts) - 1
            if final and not stat.S_ISREG(info.st_mode):
                raise OSError("not a regular file")
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if not final:
                flags |= os.O_DIRECTORY
            try:
                child = os.open(part, flags, dir_fd=directory)
            except OSError:
                # A link may have replaced the entry between stat and open.
                if stat.S_ISLNK(os.stat(part, dir_fd=directory, follow_symlinks=False).st_mode):
                    raise SymlinkConfig from None
                raise
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("not a regular file")
        if info.st_size > MAX_BYTES:
            raise TooLarge
        with os.fdopen(os.dup(directory), "rb") as stream:
            return stream.read(MAX_BYTES + 1)
    finally:
        os.close(directory)


def _home_read(path: Path) -> bytes | None:
    limit = HOME_CLAUDE_MAX_BYTES if path.name == ".claude.json" else MAX_BYTES
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise OSError("not a regular file")
            if info.st_size > limit:
                raise TooLarge
            return stream.read(limit + 1)
    except FileNotFoundError:
        return None


def _claude_mcp_only(data: dict) -> dict:
    """The remainder of ~/.claude.json is deliberately outside the scan scope."""
    result = {}
    if "mcpServers" in data:
        result["mcpServers"] = data["mcpServers"]
    projects = data.get("projects")
    if isinstance(projects, dict):
        result["projects"] = {
            name: {"mcpServers": project["mcpServers"]}
            for name, project in projects.items()
            if isinstance(project, dict) and "mcpServers" in project
        }
    return result


def load(root: Path, include_home: bool, *, home: Path | None = None):
    """Return documents, diagnostics, symlink paths, and root .env* names (never contents)."""
    documents, notes, symlinks, env_files = [], [], [], []
    root = root.resolve()
    if include_home and home is None:
        home = Path.home().resolve()
    root_fd = _open_root(root)

    def unreadable(file, name, scope):
        # Preserve presence and unknown pre-trust execution risks even when
        # inspection fails before parsing.
        if scope == "repo":
            documents.append(Document(file, name, scope, {}, unreadable=True))

    try:
        # Directory metadata only: .env files are never opened.
        scopes = []
        if root_fd is not None:
            with os.scandir(root_fd) as entries:
                for entry in entries:
                    if (entry.name.startswith(".env") and entry.name != ".envrc" and
                            not entry.name.endswith((".example", ".sample", ".template")) and
                            not entry.is_dir(follow_symlinks=False)):
                        env_files.append(str(root / entry.name))
            scopes.append(("repo", root, REPO_FILES))
        if include_home:
            scopes.append(("user", home, HOME_FILES))
        for scope, base, names in scopes:
            for name in names:
                file = str(base / name)
                kind = "TOML" if name.endswith(".toml") else "JSON"
                limit = (HOME_CLAUDE_MAX_BYTES
                         if scope == "user" and name == ".claude.json" else MAX_BYTES)

                try:
                    raw = _repo_read(root_fd, name) if scope == "repo" else _home_read(base / name)
                except SymlinkConfig:
                    symlinks.append(file)
                    continue
                except TooLarge:
                    notes.append(f"file {file} exceeds {limit // (1024 * 1024)} MB; skipped")
                    unreadable(file, name, scope)
                    continue
                except OSError:
                    notes.append(f"file {file} could not be read")
                    unreadable(file, name, scope)
                    continue
                if raw is None:
                    continue
                if len(raw) > limit:
                    notes.append(f"file {file} exceeds {limit // (1024 * 1024)} MB; skipped")
                    unreadable(file, name, scope)
                    continue
                try:
                    text = raw.decode("utf-8-sig")
                    data = tomllib.loads(text) if kind == "TOML" else json.loads(text)
                except (UnicodeError, ValueError, RecursionError) as error:
                    # Never stringify a parser exception: it may contain source text.
                    line = getattr(error, "lineno", None)
                    if line is None and isinstance(error, tomllib.TOMLDecodeError):
                        # Python 3.12 has no lineno attribute; only extract the numeric suffix.
                        match = re.search(r"\(at line (\d+), column \d+\)$", str(error))
                        line = int(match[1]) if match else text.count("\n") + 1
                    notes.append(f"file {file} is not valid {kind} (line {line or 1})")
                    # File-presence rules do not depend on successful parsing.
                    unreadable(file, name, scope)
                    continue
                if not isinstance(data, dict):
                    notes.append(f"file {file} must contain a {kind} object/table")
                    unreadable(file, name, scope)
                    continue
                if scope == "user" and name == ".claude.json":
                    data = _claude_mcp_only(data)
                documents.append(Document(file, name, scope, data))
    finally:
        if root_fd is not None:
            os.close(root_fd)
    return documents, notes, symlinks, sorted(env_files)
