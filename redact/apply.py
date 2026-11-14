"""Apply redaction rules to parsed log records."""

from __future__ import annotations

from .masking import mask_value
from .parse import dump_line, parse_line
from .rules import match_rule


def redact_record(record, rules, hits):
    """Redact a parsed record in place. Appends (path, rule) hits."""
    return _redact_value(record, (), rules, hits)


def _redact_value(value, path, rules, hits):
    rule = match_rule(rules, path)
    if rule is not None:
        hits.append((".".join(path), rule))
        return mask_value(value, rule.method)
    if isinstance(value, dict):
        for key, sub in value.items():
            value[key] = _redact_value(sub, path + (key,), rules, hits)
        return value
    if isinstance(value, list):
        # Arrays are traversed transparently: elements share the array's path.
        for index, sub in enumerate(value):
            value[index] = _redact_value(sub, path, rules, hits)
        return value
    return value


def redact_line(line, rules):
    """Redact one log line. Returns (output_line, hits).

    Lines with no rule hit are returned byte-identical to the input.
    """
    record, fmt = parse_line(line)
    if record is None:
        return line, []
    hits = []
    redact_record(record, rules, hits)
    if not hits:
        return line, hits
    return dump_line(record, fmt), hits
