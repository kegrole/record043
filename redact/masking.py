"""Irreversible, type-preserving masking primitives.

Three methods:
  keep    - keep the first 2 and last 2 characters, mask the middle.
  replace - replace the whole value with a fixed placeholder.
  hash    - "sha256:" prefix + first 16 hex chars of the SHA-256 digest.

Every method preserves the JSON type of the value: strings stay strings,
numbers stay numbers, containers keep their shape.
"""

from __future__ import annotations

import hashlib

from .rules import METHOD_HASH, METHOD_KEEP, METHOD_REPLACE

HASH_PREFIX = "sha256:"
HASH_LENGTH = 16
KEEP_HEAD = 2
KEEP_TAIL = 2
REPLACEMENT_TEXT = "***REDACTED***"


def mask_value(value, method):
    if method == METHOD_KEEP:
        return mask_keep(value)
    if method == METHOD_REPLACE:
        return mask_replace(value)
    if method == METHOD_HASH:
        return mask_hash(value)
    raise ValueError("unknown mask method: {!r}".format(method))


def mask_keep(value):
    if isinstance(value, str):
        if len(value) <= KEEP_HEAD + KEEP_TAIL:
            return "*" * max(len(value), KEEP_HEAD + KEEP_TAIL)
        return value[:KEEP_HEAD] + "*" * (len(value) - KEEP_HEAD - KEEP_TAIL) + value[-KEEP_TAIL:]
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        digits = str(value)
        if len(digits) <= KEEP_HEAD + KEEP_TAIL:
            return 0
        masked = digits[:KEEP_HEAD] + "0" * (len(digits) - KEEP_HEAD - KEEP_TAIL) + digits[-KEEP_TAIL:]
        return int(masked)
    if isinstance(value, float):
        return 0.0
    if isinstance(value, list):
        return [mask_keep(item) for item in value]
    if isinstance(value, dict):
        return {key: mask_keep(item) for key, item in value.items()}
    return value


def mask_replace(value):
    if isinstance(value, str):
        return REPLACEMENT_TEXT
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return 0
    if isinstance(value, float):
        return 0.0
    if isinstance(value, list):
        return [mask_replace(item) for item in value]
    if isinstance(value, dict):
        return {key: mask_replace(item) for key, item in value.items()}
    return value


def mask_hash(value):
    if isinstance(value, str):
        return HASH_PREFIX + _digest(value)[:HASH_LENGTH]
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return int(_digest(str(value))[:12], 16)
    if isinstance(value, float):
        return float(int(_digest(repr(value))[:12], 16))
    if isinstance(value, list):
        return [mask_hash(item) for item in value]
    if isinstance(value, dict):
        return {key: mask_hash(item) for key, item in value.items()}
    return value


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
