"""
Minimal YAML loader for corp-s2s inventory files (stdlib only).

If PyYAML is installed, :func:`load` uses ``yaml.safe_load``. Otherwise it
falls back to a small parser covering the subset our inventories use:

* block mappings and block sequences, with indentation
* flow mappings ``{a: 1}`` and flow sequences ``[a, b]``, nested and on one line
* anchors (``&name``) and aliases (``*name``)
* plain, single-quoted and double-quoted scalars, plus ``null``/``~``, ``true``/``false`` and integers
* full-line and trailing ``#`` comments

It isn't a general YAML implementation. Multi-line strings, merge keys and
tags are not supported, and loading a file that uses them raises ``ValueError``.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:  # pragma: no cover - exercised only when PyYAML is present
    import yaml as _pyyaml  # type: ignore
except Exception:  # pragma: no cover
    _pyyaml = None


def load(path) -> Any:
    """Load a YAML file, preferring PyYAML when it is available."""
    text = Path(path).read_text(encoding="utf-8")
    if _pyyaml is not None:
        return _pyyaml.safe_load(text)
    return loads(text)


def loads(text: str) -> Any:
    """Parse YAML text using the built-in subset parser."""
    return _Parser(text).parse()


# ---------------------------------------------------------------------------

_INT = re.compile(r"^[-+]?\d+$")


def _strip_comment(line: str) -> str:
    """Remove a trailing ``# comment`` that is outside quotes."""
    out, quote = [], None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _scalar(tok: str) -> Any:
    t = tok.strip()
    if t == "" or t in ("~", "null", "Null", "NULL"):
        return None
    if t in ("true", "True", "TRUE", "yes", "Yes"):
        return True
    if t in ("false", "False", "FALSE", "no", "No"):
        return False
    if len(t) >= 2 and t[0] == t[-1] and t[0] in ("'", '"'):
        body = t[1:-1]
        return body.replace("''", "'") if t[0] == "'" else bytes(body, "utf-8").decode("unicode_escape")
    if _INT.match(t):
        return int(t)
    return t


def _split_key(content: str) -> Optional[Tuple[str, str]]:
    """Split ``key: rest`` at the first top-level colon. Returns None if this isn't a mapping line."""
    depth, quote = 0, None
    for i, ch in enumerate(content):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == ":" and depth == 0 and (i + 1 == len(content) or content[i + 1] in " \t"):
            return content[:i].strip(), content[i + 1:].strip()
    return None


class _Parser:
    def __init__(self, text: str):
        self.lines: List[Tuple[int, str]] = []
        for raw in text.splitlines():
            if raw.strip().startswith("#") or not raw.strip():
                continue
            stripped = _strip_comment(raw)
            if not stripped.strip():
                continue
            if "\t" in raw[: len(raw) - len(raw.lstrip())]:
                raise ValueError("tabs are not allowed for YAML indentation")
            indent = len(stripped) - len(stripped.lstrip(" "))
            self.lines.append((indent, stripped.strip()))
        self.anchors: Dict[str, Any] = {}
        self.i = 0

    def parse(self) -> Any:
        if not self.lines:
            return None
        if self.lines[0][1] == "---":
            self.i = 1
        return self._block(self.lines[self.i][0]) if self.i < len(self.lines) else None

    # -- block structures ------------------------------------------------
    def _block(self, indent: int) -> Any:
        _, content = self.lines[self.i]
        if content == "-" or content.startswith("- "):
            return self._seq(indent)
        return self._map(indent)

    def _map(self, indent: int) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        while self.i < len(self.lines):
            ind, content = self.lines[self.i]
            if ind < indent:
                break
            if ind > indent:
                raise ValueError(f"unexpected indentation at: {content!r}")
            if content.startswith("- "):
                break
            kv = _split_key(content)
            if kv is None:
                raise ValueError(f"expected 'key: value' at: {content!r}")
            key, rest = kv
            self.i += 1
            out[str(_scalar(key))] = self._value(rest, indent)
        return out

    def _seq(self, indent: int) -> List[Any]:
        out: List[Any] = []
        while self.i < len(self.lines):
            ind, content = self.lines[self.i]
            if ind != indent or not (content == "-" or content.startswith("- ")):
                break
            rest = content[1:].strip()
            if rest == "":
                self.i += 1
                out.append(self._child(indent))
            elif _split_key(rest) and not rest.startswith(("{", "[", "'", '"')):
                # "- key: value" starts a mapping whose keys sit at indent + 2
                self.lines[self.i] = (indent + 2, rest)
                out.append(self._map(indent + 2))
            else:
                self.i += 1
                out.append(self._inline(rest))
        return out

    def _child(self, parent_indent: int) -> Any:
        if self.i >= len(self.lines):
            return None
        ind, content = self.lines[self.i]
        if ind > parent_indent:
            return self._block(ind)
        # YAML allows a block sequence at the same indent as its parent key
        if ind == parent_indent and (content == "-" or content.startswith("- ")):
            return self._seq(ind)
        return None

    def _value(self, rest: str, indent: int) -> Any:
        anchor = None
        m = re.match(r"^&([A-Za-z0-9_\-]+)\s*(.*)$", rest)
        if m:
            anchor, rest = m.group(1), m.group(2)
        if rest == "":
            val = self._child(indent)
        else:
            rest = self._join_flow(rest)
            val = self._inline(rest)
        if anchor:
            self.anchors[anchor] = val
        return val

    def _join_flow(self, rest: str) -> str:
        """Join continuation lines of a flow collection that spans several lines."""
        def balance(s: str) -> int:
            return sum(s.count(c) for c in "[{") - sum(s.count(c) for c in "]}")
        while rest[:1] in ("[", "{") and balance(rest) > 0 and self.i < len(self.lines):
            rest += " " + self.lines[self.i][1]
            self.i += 1
        return rest

    # -- inline values -----------------------------------------------------
    def _inline(self, text: str) -> Any:
        text = text.strip()
        m = re.match(r"^&([A-Za-z0-9_\-]+)\s+(.*)$", text)
        if m:
            val = self._inline(m.group(2))
            self.anchors[m.group(1)] = val
            return val
        if text.startswith("*"):
            name = text[1:].strip()
            if name not in self.anchors:
                raise ValueError(f"unknown alias *{name}")
            return copy.deepcopy(self.anchors[name])
        if text.startswith(("{", "[")):
            val, pos = self._flow(text, 0)
            if text[pos:].strip():
                raise ValueError(f"trailing characters after flow value: {text[pos:]!r}")
            return val
        if text.startswith(("|", ">", "!", "<<")):
            raise ValueError(f"unsupported YAML feature in: {text!r}")
        return _scalar(text)

    def _flow(self, s: str, pos: int) -> Tuple[Any, int]:
        pos = self._ws(s, pos)
        ch = s[pos]
        if ch == "{":
            out: Dict[str, Any] = {}
            pos += 1
            while True:
                pos = self._ws(s, pos)
                if s[pos] == "}":
                    return out, pos + 1
                key, pos = self._flow_scalar(s, pos, key=True)
                pos = self._ws(s, pos)
                if s[pos] != ":":
                    raise ValueError(f"expected ':' in flow mapping near {s[pos:pos + 20]!r}")
                val, pos = self._flow(s, pos + 1)
                out[str(key)] = val
                pos = self._ws(s, pos)
                if s[pos] == ",":
                    pos += 1
                elif s[pos] != "}":
                    raise ValueError(f"expected ',' or '}}' near {s[pos:pos + 20]!r}")
        if ch == "[":
            items: List[Any] = []
            pos += 1
            while True:
                pos = self._ws(s, pos)
                if s[pos] == "]":
                    return items, pos + 1
                val, pos = self._flow(s, pos)
                items.append(val)
                pos = self._ws(s, pos)
                if s[pos] == ",":
                    pos += 1
                elif s[pos] != "]":
                    raise ValueError(f"expected ',' or ']' near {s[pos:pos + 20]!r}")
        if ch == "*":
            m = re.match(r"\*([A-Za-z0-9_\-]+)", s[pos:])
            if not m or m.group(1) not in self.anchors:
                raise ValueError("unknown alias in flow value")
            return copy.deepcopy(self.anchors[m.group(1)]), pos + m.end()
        return self._flow_scalar(s, pos)

    @staticmethod
    def _ws(s: str, pos: int) -> int:
        while pos < len(s) and s[pos] in " \t":
            pos += 1
        if pos >= len(s):
            raise ValueError("unterminated flow collection")
        return pos

    @staticmethod
    def _flow_scalar(s: str, pos: int, key: bool = False) -> Tuple[Any, int]:
        if s[pos] in ("'", '"'):
            q = s[pos]
            end = pos + 1
            while end < len(s) and s[end] != q:
                end += 2 if s[end] == "\\" and q == '"' else 1
            return _scalar(s[pos:end + 1]), end + 1
        end = pos
        while end < len(s):
            c = s[end]
            if c in ",]}":
                break
            if c == ":" and (end + 1 == len(s) or s[end + 1] in " \t,]}"):
                break
            end += 1
        return _scalar(s[pos:end]), end
