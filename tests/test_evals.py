import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from evals.loader import EvalCase, load_cases
from evals.runner import (
    EvalCaseResult,
    MissingCredentialError,
    aggregate_report,
    load_api_key,
    write_report,
)


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


class TestEvalRunnerPrimitives(unittest.TestCase):
    def test_environment_credential_takes_priority_over_dotenv(self):
        """A deployed environment must override a project-local credential file."""
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, ".env").write_text("JEV_API_KEY=dotenv-key\n", encoding="utf-8")
            with patch.dict(os.environ, {"JEV_API_KEY": "environment-key"}, clear=False):
                self.assertEqual(load_api_key(directory), "environment-key")

    def test_dotenv_supports_export_comments_and_quoted_values_without_output(self):
        """Project-local credentials are parsed silently when the environment is unset."""
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, ".env").write_text(
                "# local development only\nexport JEV_API_KEY='dotenv-key' # comment\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {}, clear=True):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(load_api_key(directory), "dotenv-key")
        self.assertEqual(output.getvalue(), "")

    def test_missing_credential_raises_actionable_error(self):
        """A missing credential stops evaluation before a client can be created."""
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(MissingCredentialError, "JEV_API_KEY"):
                    load_api_key(directory)

    def test_report_aggregation_and_serialization_keep_sensitive_case_data_out(self):
        """Reports retain decision metrics but never prompts, candidates, or raw responses."""
        report = aggregate_report(
            suite="classify",
            model="jev-latest",
            case_results=(
                EvalCaseResult(
                    id="case-1",
                    expected="orders",
                    predicted="orders",
                    status="resolved",
                    confidence=0.92,
                    latency_ms=12.5,
                    passed=True,
                ),
                EvalCaseResult(
                    id="case-2",
                    expected="human",
                    predicted=None,
                    status="uncertain",
                    confidence=None,
                    latency_ms=4.0,
                    passed=False,
                ),
            ),
        )

        self.assertEqual(
            (
                report.total,
                report.passed,
                report.incorrect,
                report.uncertain,
                report.unavailable,
            ),
            (2, 1, 0, 1, 0),
        )
        with tempfile.TemporaryDirectory() as directory:
            report_path = write_report(report, directory)
            payload = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertTrue(report_path.name.startswith("classify-"))
        self.assertEqual(payload["cases"][0]["id"], "case-1")
        serialized = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("input", serialized)
        self.assertNotIn("candidates", serialized)
        self.assertNotIn("raw_response", serialized)


if __name__ == "__main__":
    unittest.main()
