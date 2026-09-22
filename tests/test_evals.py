import json
from pathlib import Path
import tempfile
import unittest

from evals.loader import EvalCase, load_cases


class TestEvalCaseLoader(unittest.TestCase):
    def _write_cases(self, directory, cases):
        path = Path(directory) / "cases.json"
        path.write_text(json.dumps(cases, ensure_ascii=False), encoding="utf-8")
        return path

    def test_rejects_duplicate_case_ids(self):
        """A duplicated ID must not let one scenario silently replace another."""
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_cases(
                directory,
                [
                    {"id": "same", "input": "查询订单", "candidates": {"orders": "订单服务"}, "expected": "orders"},
                    {"id": "same", "input": "取消订单", "candidates": {"orders": "订单服务"}, "expected": "orders"},
                ],
            )

            with self.assertRaisesRegex(ValueError, "Duplicate case id: same"):
                load_cases(path)

    def test_rejects_case_without_expected_value(self):
        """An incomplete scenario cannot be used to inflate evaluation results."""
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_cases(
                directory,
                [{"id": "missing-expected", "input": "查询订单", "candidates": {"orders": "订单服务"}}],
            )

            with self.assertRaisesRegex(ValueError, "Case missing-expected is missing expected"):
                load_cases(path)

    def test_rejects_non_string_candidate_descriptions(self):
        """Candidate metadata must remain valid text for public SDK APIs."""
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_cases(
                directory,
                [{"id": "bad-candidate", "input": "查询订单", "candidates": {"orders": 1}, "expected": "orders"}],
            )

            with self.assertRaisesRegex(ValueError, "Case bad-candidate has a non-string candidate description"):
                load_cases(path)

    def test_loads_valid_cases_as_frozen_records(self):
        """A valid corpus preserves the prompt, candidates, and expected decision."""
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_cases(
                directory,
                [{"id": "order-status", "input": "订单到哪了", "candidates": {"orders": "查询订单状态"}, "expected": "orders"}],
            )

            cases = load_cases(path)

        self.assertEqual(
            cases,
            (
                EvalCase(
                    id="order-status",
                    input="订单到哪了",
                    candidates={"orders": "查询订单状态"},
                    expected="orders",
                ),
            ),
        )
        with self.assertRaisesRegex(AttributeError, "cannot assign"):
            cases[0].expected = "other"


if __name__ == "__main__":
    unittest.main()
