"""Redaction rules: loading from a rules file and key-path matching.

Path syntax: dot-separated segments. A segment is a literal key name,
"*" (matches exactly one segment) or "**" (matches zero or more
segments). Array elements are traversed transparently: they do not add
a path segment, so "items.password" matches every element's "password"
inside the "items" array.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

METHOD_KEEP = "keep"
METHOD_REPLACE = "replace"
METHOD_HASH = "hash"
VALID_METHODS = (METHOD_KEEP, METHOD_REPLACE, METHOD_HASH)


@dataclass(frozen=True)
class Rule:
    path: str
    method: str
    segments: tuple


def load_rules(source):
    """Load rules from a JSON file: {"rules": [{"path": ..., "method": ...}]}."""
    with open(source, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    entries = data.get("rules")
    if not isinstance(entries, list):
        raise ValueError("rules file must contain a 'rules' list")
    return [parse_rule(entry) for entry in entries]


def parse_rule(entry):
    path = entry["path"]
    method = entry["method"]
    if method not in VALID_METHODS:
        raise ValueError("unknown mask method: {!r} (expected one of {})".format(method, VALID_METHODS))
    segments = tuple(part for part in path.split(".") if part != "")
    if not segments:
        raise ValueError("rule path must not be empty")
    return Rule(path=path, method=method, segments=segments)


def match_rule(rules, path_segments):
    """Return the first rule matching the given path tuple, or None."""
    for rule in rules:
        if _match_segments(rule.segments, path_segments):
            return rule
    return None


def _match_segments(pattern, path):
    if not pattern:
        return not path
    head, rest = pattern[0], pattern[1:]
    if head == "**":
        if _match_segments(rest, path):
            return True
        return bool(path) and _match_segments(pattern, path[1:])
    if not path:
        return False
    if head == "*" or head == path[0]:
        return _match_segments(rest, path[1:])
    return False
