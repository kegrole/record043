import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redact import cli
from redact.apply import redact_line
from redact.masking import mask_hash, mask_keep, mask_replace
from redact.parse import FORMAT_JSON, FORMAT_LOGFMT, parse_line
from redact.rules import load_rules, match_rule, parse_rule

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_LOGS = os.path.join(REPO_ROOT, "demo", "logs.jsonl")
DEMO_RULES = os.path.join(REPO_ROOT, "demo", "redact_rules.json")

SENSITIVE_VALUES = [
    "Sup3rSecret!",
    "tok_abcdef123456",
    "Bearer abcdef1234567890",
    "session=xyz987654321",
    "110101199003077799",
    "BatchPass99",
    "alice.wonderland@example.com",
    "13812345678",
]


def read_lines(path):
    with open(path, "r", encoding="utf-8") as fh:
        return [line.rstrip("\n") for line in fh if line.strip()]


def run_redaction(rules_path):
    out_dir = tempfile.mkdtemp()
    out_path = os.path.join(out_dir, "redacted.jsonl")
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        exit_code = cli.main(["--input", DEMO_LOGS, "--rules", rules_path, "--out", out_path])
    assert exit_code == 0
    return read_lines(out_path), stdout.getvalue()


class RedactDemoTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.input_lines = read_lines(DEMO_LOGS)
        cls.output_lines, cls.summary = run_redaction(DEMO_RULES)
        cls.output_text = "\n".join(cls.output_lines) + "\n"

    def test_fixture_has_8_lines(self):
        self.assertEqual(len(self.input_lines), 8)
        self.assertEqual(len(self.output_lines), 8)

    def test_exactly_6_lines_redacted(self):
        changed = [i for i, (a, b) in enumerate(zip(self.input_lines, self.output_lines)) if a != b]
        self.assertEqual(len(changed), 6)
        # The email line (index 4) and the phone line (index 5) must be redacted.
        self.assertIn(4, changed)
        self.assertIn(5, changed)

    def test_normal_lines_byte_identical(self):
        self.assertEqual(self.output_lines[6], self.input_lines[6])
        self.assertEqual(self.output_lines[7], self.input_lines[7])

    def test_no_4_contiguous_chars_of_any_original(self):
        for original in SENSITIVE_VALUES:
            self.assertGreaterEqual(len(original), 8)
            for start in range(len(original) - 3):
                fragment = original[start:start + 4]
                self.assertNotIn(fragment, self.output_text,
                                 "fragment {!r} of {!r} leaked".format(fragment, original))

    def test_key_order_preserved(self):
        for raw_in, raw_out in zip(self.input_lines, self.output_lines):
            obj_in, fmt_in = parse_line(raw_in)
            obj_out, fmt_out = parse_line(raw_out)
            self.assertEqual(fmt_in, fmt_out)
            self.assertEqual(list(obj_in.keys()), list(obj_out.keys()))
        # Nested object key order must also be preserved.
        nested_in = json.loads(self.input_lines[2])
        nested_out = json.loads(self.output_lines[2])
        self.assertEqual(list(nested_in["user"].keys()), list(nested_out["user"].keys()))

    def test_numeric_field_stays_numeric(self):
        phone_out = json.loads(self.output_lines[5])
        self.assertIsInstance(phone_out["phone"], int)
        self.assertNotIsInstance(phone_out["phone"], bool)
        self.assertEqual(phone_out["phone"], 0)

    def test_array_element_password_redacted(self):
        items = json.loads(self.output_lines[3])["items"]
        self.assertEqual(items[0]["password"], "Ba*******99")
        self.assertNotIn("BatchPass99", self.output_text)
        # Untouched sibling element stays as-is.
        self.assertEqual(items[1], {"sku": "b2", "note": "ok"})

    def test_unmatched_nested_key_preserved(self):
        user = json.loads(self.output_lines[2])["user"]
        self.assertEqual(user["name"], "carol")
        self.assertEqual(user["id_card"], "11**************99")

    def test_rules_file_drives_redaction(self):
        with open(DEMO_RULES, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        data["rules"] = [r for r in data["rules"] if r["path"] != "**.email"]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(data, fh)
            alt_rules = fh.name
        try:
            alt_lines, _ = run_redaction(alt_rules)
        finally:
            os.unlink(alt_rules)
        # Email line is no longer redacted; everything else still is.
        self.assertEqual(alt_lines[4], self.input_lines[4])
        changed = [i for i, (a, b) in enumerate(zip(self.input_lines, alt_lines)) if a != b]
        self.assertEqual(len(changed), 5)

    def test_cli_summary_line(self):
        self.assertIn("lines=8", self.summary)
        self.assertIn("redacted_lines=6", self.summary)
        self.assertIn("redacted_fields=8", self.summary)
        self.assertIn("**.password=2", self.summary)
        self.assertIn("**.email=1", self.summary)


class ParseTest(unittest.TestCase):
    def test_json_line(self):
        record, fmt = parse_line('{"a": 1, "b": "x"}')
        self.assertEqual(fmt, FORMAT_JSON)
        self.assertEqual(record, {"a": 1, "b": "x"})

    def test_logfmt_line(self):
        record, fmt = parse_line('ts=now level=info msg="hello world" n=42')
        self.assertEqual(fmt, FORMAT_LOGFMT)
        self.assertEqual(record, {"ts": "now", "level": "info", "msg": "hello world", "n": "42"})


class RuleMatchTest(unittest.TestCase):
    def setUp(self):
        self.rules = [
            parse_rule({"path": "a.b.c", "method": "keep"}),
            parse_rule({"path": "user.*", "method": "replace"}),
            parse_rule({"path": "**.token", "method": "hash"}),
        ]

    def hit(self, path):
        rule = match_rule(self.rules, tuple(path.split(".")))
        return rule.method if rule else None

    def test_exact_path(self):
        self.assertEqual(self.hit("a.b.c"), "keep")
        self.assertIsNone(self.hit("a.b"))
        self.assertIsNone(self.hit("a.b.c.d"))

    def test_single_wildcard(self):
        self.assertEqual(self.hit("user.name"), "replace")
        self.assertIsNone(self.hit("user"))
        self.assertIsNone(self.hit("user.a.b"))

    def test_multi_wildcard(self):
        self.assertEqual(self.hit("token"), "hash")
        self.assertEqual(self.hit("x.token"), "hash")
        self.assertEqual(self.hit("x.y.z.token"), "hash")
        self.assertIsNone(self.hit("tokenx"))

    def test_first_match_wins(self):
        rules = [
            parse_rule({"path": "**.secret", "method": "hash"}),
            parse_rule({"path": "**.secret", "method": "keep"}),
        ]
        self.assertEqual(match_rule(rules, ("secret",)).method, "hash")


class MaskingTest(unittest.TestCase):
    def test_keep_string(self):
        self.assertEqual(mask_keep("Sup3rSecret!"), "Su********t!")
        self.assertEqual(mask_keep("abcd"), "****")
        self.assertEqual(mask_keep("abcde"), "ab*de")

    def test_keep_number_stays_number(self):
        masked = mask_keep(13812345678)
        self.assertIsInstance(masked, int)
        self.assertEqual(masked, 13000000078)

    def test_replace_types(self):
        self.assertEqual(mask_replace("whatever"), "***REDACTED***")
        self.assertEqual(mask_replace(13812345678), 0)
        self.assertIsInstance(mask_replace(13812345678), int)
        self.assertEqual(mask_replace(1.5), 0.0)
        self.assertIsInstance(mask_replace(1.5), float)

    def test_hash_format_and_irreversibility(self):
        masked = mask_hash("alice.wonderland@example.com")
        self.assertTrue(masked.startswith("sha256:"))
        self.assertEqual(len(masked), len("sha256:") + 16)
        self.assertNotIn("alice", masked)
        self.assertEqual(masked, mask_hash("alice.wonderland@example.com"))

    def test_hash_number_stays_number(self):
        masked = mask_hash(13812345678)
        self.assertIsInstance(masked, int)
        self.assertNotEqual(masked, 13812345678)


class LogfmtRedactTest(unittest.TestCase):
    def test_logfmt_line_redacted_and_reserialized(self):
        rules = [parse_rule({"path": "**.email", "method": "hash"})]
        out, hits = redact_line('msg="contact sync" email=alice@example.com', rules)
        self.assertEqual(len(hits), 1)
        record, fmt = parse_line(out)
        self.assertEqual(fmt, FORMAT_LOGFMT)
        self.assertEqual(record["msg"], "contact sync")
        self.assertTrue(record["email"].startswith("sha256:"))
        self.assertEqual(list(record.keys()), ["msg", "email"])

    def test_logfmt_line_without_hit_byte_identical(self):
        line = 'ts=now level=info msg="health check ok"'
        out, hits = redact_line(line, [parse_rule({"path": "**.email", "method": "hash"})])
        self.assertEqual(hits, [])
        self.assertEqual(out, line)


if __name__ == "__main__":
    unittest.main()
