"""Bounded discovery of writable user-owned Steam Proton installations."""

import os
from pathlib import Path
import stat


_MAX_VDF = 1024 * 1024
_MAX_ENTRIES = 4096
_MAX_TOOLS = 256


def _tokens(text):
    index = 0
    count = 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = len(text) if end < 0 else end + 1
            continue
        if text[index] in "{}":
            yield text[index]
            index += 1
        elif text[index] == '"':
            index += 1
            chars = []
            while index < len(text) and text[index] != '"':
                if text[index] == "\\" and index + 1 < len(text) and text[index + 1] in ('"', "\\"):
                    index += 1
                chars.append(text[index])
                index += 1
                if len(chars) > 4096:
                    raise ValueError("VDF token too large")
            if index == len(text):
                raise ValueError("unterminated VDF string")
            index += 1
            yield "".join(chars)
        else:
            raise ValueError("invalid VDF token")
        count += 1
        if count > 32768:
            raise ValueError("too many VDF tokens")


def _document(text):
    tokens = iter(_tokens(text))

    def group(depth, closing):
        if depth > 16:
            raise ValueError("VDF nesting limit")
        values = {}
        for key in tokens:
            if key == "}":
                if closing:
                    return values
                raise ValueError("unexpected VDF close")
            if key == "{" or key in values:
                raise ValueError("invalid or duplicate VDF key")
            value = next(tokens, None)
            if value is None or value == "}":
                raise ValueError("incomplete VDF entry")
            values[key] = group(depth + 1, True) if value == "{" else value
        if closing:
            raise ValueError("unclosed VDF object")
        return values

    return group(0, False)


def _library_paths(path):
    try:
        with path.open("rb") as source:
            data = source.read(_MAX_VDF + 1)
        if len(data) > _MAX_VDF:
            raise ValueError("library list too large")
        document = _document(data.decode("utf-8-sig"))
        folders = document.get("libraryfolders")
        if not isinstance(folders, dict):
            raise ValueError("missing library list")
        result = []
        for key, value in folders.items():
            if not key.isascii() or not key.isdigit():
                continue
            path_value = value.get("path") if isinstance(value, dict) else value
            if isinstance(path_value, str) and Path(path_value).is_absolute():
                result.append(Path(path_value))
        return result
    except FileNotFoundError:
        return []


def _tool(path):
    try:
        info = path.lstat()
        return (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and os.access(path, os.W_OK)
                and (path / "proton").is_file()
                and (path / "user_settings.sample.py").is_file())
    except OSError:
        return False


def discover(roots):
    """Return candidate paths and diagnostics; never alter a tool here."""
    if not isinstance(roots, list) or len(roots) > 64:
        raise ValueError("invalid Steam roots")
    libraries = set()
    diagnostics = set()
    for raw in roots:
        if not isinstance(raw, str) or not Path(raw).is_absolute() or len(raw) > 4096:
            raise ValueError("invalid Steam root")
        try:
            root = Path(raw).resolve()
        except (OSError, RuntimeError):
            diagnostics.add("root_unavailable")
            continue
        libraries.add(root)
        try:
            libraries.update(path.resolve() for path in _library_paths(root / "steamapps" / "libraryfolders.vdf"))
        except (OSError, ValueError, UnicodeError, RecursionError, RuntimeError):
            diagnostics.add("library_list_unavailable")
    if len(libraries) > 128:
        raise ValueError("too many Steam libraries")
    tools = set()
    visited = 0
    for root in sorted(libraries):
        for directory in (root / "compatibilitytools.d", root / "steamapps" / "common"):
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        visited += 1
                        if visited > _MAX_ENTRIES:
                            raise ValueError("Steam directory entry limit")
                        path = Path(entry.path)
                        if _tool(path):
                            tools.add(str(path))
                            if len(tools) > _MAX_TOOLS or sum(len(str(tool).encode("utf-8")) for tool in tools) > 12000:
                                raise ValueError("Proton tool limit")
            except FileNotFoundError:
                continue
            except OSError:
                diagnostics.add("tool_directory_unavailable")
    return sorted(tools), sorted(diagnostics)


def default_roots(home, steam_dir=None):
    if not isinstance(home, str) or not Path(home).is_absolute():
        raise ValueError("invalid home directory")
    root = Path(home)
    candidates = [root / ".steam" / "steam", root / ".local" / "share" / "Steam",
                  root / ".var" / "app" / "com.valvesoftware.Steam" / ".local" / "share" / "Steam"]
    if steam_dir:
        if not Path(steam_dir).is_absolute():
            raise ValueError("invalid Steam directory")
        candidates.append(Path(steam_dir))
    return [str(path) for path in candidates]
