"""Parsing and serialization of JSON-lines and logfmt log records."""

from __future__ import annotations

import json
import re

FORMAT_JSON = "json"
FORMAT_LOGFMT = "logfmt"

_LOGFMT_PAIR = re.compile(r'([A-Za-z0-9_.\-/]+)=("(?:[^"\\]|\\.)*"|\S*)')


def parse_line(line):
    """Parse one log line. Returns (record, fmt) or (None, None) for blanks."""
    text = line.strip()
    if not text:
        return None, None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        obj = None
    if isinstance(obj, dict):
        return obj, FORMAT_JSON
    return parse_logfmt(text), FORMAT_LOGFMT


def parse_logfmt(text):
    record = {}
    for match in _LOGFMT_PAIR.finditer(text):
        record[match.group(1)] = _decode_value(match.group(2))
    return record


def _decode_value(raw):
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw[1:-1]
    return raw


def dump_line(record, fmt):
    if fmt == FORMAT_JSON:
        return json.dumps(record, ensure_ascii=False)
    return dump_logfmt(record)


def dump_logfmt(record):
    return " ".join("{}={}".format(key, _encode_value(value)) for key, value in record.items())


def _encode_value(value):
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return repr(value)
    text = str(value)
    if text == "" or any(ch.isspace() or ch in '="' for ch in text):
        return json.dumps(text, ensure_ascii=False)
    return text
