"""Command line entry point: redact a log file according to a rules file."""

from __future__ import annotations

import argparse
import os
import sys

from .apply import redact_line
from .report import Report
from .rules import load_rules


def build_parser():
    parser = argparse.ArgumentParser(
        prog="redact",
        description="Redact sensitive fields from JSON-lines / logfmt logs.",
    )
    parser.add_argument("--input", required=True, help="input log file (jsonl or logfmt)")
    parser.add_argument("--rules", required=True, help="JSON rules file")
    parser.add_argument("--out", required=True, help="output file for redacted logs")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    rules = load_rules(args.rules)
    report = Report()
    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    with open(args.input, "r", encoding="utf-8") as fin, open(args.out, "w", encoding="utf-8") as fout:
        for raw in fin:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            out_line, hits = redact_line(line, rules)
            report.record(hits)
            fout.write(out_line + "\n")
    print(report.summary())
    return 0


if __name__ == "__main__":
    sys.exit(main())
