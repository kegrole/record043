"""Run statistics for a redaction pass."""

from __future__ import annotations

from collections import Counter


class Report:
    def __init__(self):
        self.lines = 0
        self.redacted_lines = 0
        self.redacted_fields = 0
        self.rule_hits = Counter()

    def record(self, hits):
        self.lines += 1
        if hits:
            self.redacted_lines += 1
        self.redacted_fields += len(hits)
        for _path, rule in hits:
            self.rule_hits[rule.path] += 1

    def summary(self):
        distribution = ", ".join(
            "{}={}".format(path, self.rule_hits[path]) for path in sorted(self.rule_hits)
        ) or "none"
        return "lines={} redacted_lines={} redacted_fields={} rule_hits: {}".format(
            self.lines, self.redacted_lines, self.redacted_fields, distribution
        )
