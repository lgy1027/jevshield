import io
import importlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from evals.loader import EvalCase, load_cases
from evals.runner import (
    EvalCaseResult,
    MissingCredentialError,
    aggregate_report,
    load_api_key,
    run_classify_suite,
    run_route_suite,
    write_report,
)
from jevshield import ChoiceAnswer, DecisionStatus


class RecordingDecisionClient:
    """Network-free DecisionClient double with scripted public answers."""

    def __init__(self, answers):
        self._answers = iter(answers)
        self.calls = []

    def choose(self, state, question):
        self.calls.append((state, question))
        return next(self._answers)

    async def achoose(self, state, question):
        raise AssertionError("Synchronous evaluation suites must use choose().")


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

    def test_report_writer_rejects_path_separated_suite_name(self):
        """A suite name must not turn the report filename into a path escape."""
        report = aggregate_report(
            suite="../outside/report",
            model="jev-latest",
            case_results=(),
        )
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory, "reports")
            outside_path = Path(directory, "outside", "report.json")

            with self.assertRaisesRegex(ValueError, "Unsupported suite"):
                write_report(report, report_dir)

            self.assertFalse(outside_path.exists())


class TestPublicDecisionSuites(unittest.TestCase):
    def test_classify_suite_uses_public_classifier_and_separates_outcomes(self):
        """Wrong classification, uncertainty, and outages must not count as passes."""
        case_text = "Confidential request text must never appear in reports"
        cases = (
            EvalCase("right", case_text, {"orders": "Order work", "human": "Review"}, "orders"),
            EvalCase("wrong", case_text, {"orders": "Order work", "human": "Review"}, "orders"),
            EvalCase("uncertain", case_text, {"orders": "Order work", "human": "Review"}, "orders"),
            EvalCase("offline", case_text, {"orders": "Order work", "human": "Review"}, "orders"),
        )
        client = RecordingDecisionClient(
            (
                ChoiceAnswer("orders", 0.9, DecisionStatus.RESOLVED, 1.0, "fake"),
                ChoiceAnswer("human", 0.8, DecisionStatus.RESOLVED, 2.0, "fake"),
                ChoiceAnswer(None, 0.0, DecisionStatus.UNCERTAIN, 3.0, "fake"),
                ChoiceAnswer(None, 0.0, DecisionStatus.UNAVAILABLE, 4.0, "fake"),
            )
        )

        report = run_classify_suite(cases, client, model="fake-model")

        self.assertEqual((report.total, report.passed, report.incorrect, report.uncertain, report.unavailable), (4, 1, 1, 1, 1))
        self.assertEqual([question.name for _, question in client.calls], ["intent"] * 4)
        self.assertTrue(all(question.criteria == {"orders": "Order work", "human": "Review"} for _, question in client.calls))
        self.assertNotIn(case_text, json.dumps(report.to_dict(), ensure_ascii=False))

    def test_route_suite_uses_public_router_and_requires_resolved_exact_match(self):
        """Routes pass only when the public Router resolves the expected route key."""
        cases = (
            EvalCase("right", "Route private request", {"orders": "Order work", "human": "Review"}, "orders"),
            EvalCase("wrong", "Route private request", {"orders": "Order work", "human": "Review"}, "orders"),
        )
        client = RecordingDecisionClient(
            (
                ChoiceAnswer("orders", 0.9, DecisionStatus.RESOLVED, 1.0, "fake"),
                ChoiceAnswer("human", 0.9, DecisionStatus.RESOLVED, 2.0, "fake"),
            )
        )

        report = run_route_suite(cases, client, model="fake-model")

        self.assertEqual((report.total, report.passed, report.incorrect, report.uncertain, report.unavailable), (2, 1, 1, 0, 0))
        self.assertEqual([question.name for _, question in client.calls], ["route", "route"])
        self.assertEqual([case.predicted for case in report.cases], ["orders", "human"])


class TestEvalCli(unittest.TestCase):
    def _report(self, suite, *, passed=True):
        return aggregate_report(
            suite=suite,
            model="fake-model",
            case_results=(
                EvalCaseResult(
                    id="case-1",
                    expected="orders",
                    predicted="orders" if passed else "human",
                    status="resolved",
                    confidence=0.9,
                    latency_ms=1.0,
                    passed=passed,
                ),
            ),
        )

    def test_cli_runs_requested_suite_and_prints_only_aggregate_and_report_path(self):
        """The manual command exposes metrics and a report location, not case content."""
        run = importlib.import_module("evals.run")
        report = self._report("classify")
        with tempfile.TemporaryDirectory() as directory, patch.object(
            run, "load_api_key", return_value="test-key"
        ), patch.object(run, "JevClient") as client_type, patch.object(
            run, "load_cases", return_value=()
        ), patch.object(run, "run_classify_suite", return_value=report) as classify, patch.object(
            run, "write_report", return_value=Path(directory, "classify-safe.json")
        ) as write:
            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = run.main(
                    ["--suite", "classify", "--report-dir", directory, "--min-confidence", "0.75"]
                )

        self.assertEqual(exit_code, 0)
        client_type.assert_called_once_with(api_key="test-key")
        classify.assert_called_once_with(
            (),
            client_type.return_value,
            model=client_type.return_value.model,
            min_confidence=0.75,
        )
        write.assert_called_once_with(report, Path(directory))
        rendered = output.getvalue()
        self.assertIn("total=1 passed=1 incorrect=0 uncertain=0 unavailable=0", rendered)
        self.assertIn("report=", rendered)
        self.assertNotIn("test-key", rendered)
        self.assertNotIn("case-1", rendered)

    def test_cli_combines_both_suites_for_all(self):
        """The combined option writes one report with both non-sensitive outcomes."""
        run = importlib.import_module("evals.run")
        classify_report = self._report("classify")
        route_report = self._report("route")
        with tempfile.TemporaryDirectory() as directory, patch.object(
            run, "load_api_key", return_value="test-key"
        ), patch.object(run, "JevClient") as client_type, patch.object(
            run, "load_cases", return_value=()
        ), patch.object(
            run, "run_classify_suite", return_value=classify_report
        ) as classify, patch.object(
            run, "run_route_suite", return_value=route_report
        ) as route, patch.object(
            run, "write_report", return_value=Path(directory, "all-safe.json")
        ) as write:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(run.main(["--suite", "all", "--report-dir", directory]), 0)

        classify.assert_called_once()
        route.assert_called_once()
        report = write.call_args.args[0]
        self.assertEqual((report.suite, report.total, report.passed), ("all", 2, 2))
        self.assertEqual(write.call_args.args[1], Path(directory))
        self.assertEqual(client_type.return_value.close.call_count, 1)

    def test_cli_returns_nonzero_when_any_result_is_incorrect(self):
        """A completed but incorrect decision makes a live evaluation fail."""
        run = importlib.import_module("evals.run")
        with tempfile.TemporaryDirectory() as directory, patch.object(
            run, "load_api_key", return_value="test-key"
        ), patch.object(run, "JevClient"), patch.object(
            run, "load_cases", return_value=()
        ), patch.object(run, "run_route_suite", return_value=self._report("route", passed=False)), patch.object(
            run, "write_report", return_value=Path(directory, "route-safe.json")
        ):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(run.main(["--suite", "route", "--report-dir", directory]), 1)

    def test_cli_returns_nonzero_without_a_configured_key(self):
        """Credential validation happens before a client or suite can be run."""
        run = importlib.import_module("evals.run")
        with patch.object(run, "load_api_key", side_effect=MissingCredentialError("key required")), patch.object(
            run, "JevClient"
        ) as client_type:
            with redirect_stderr(io.StringIO()):
                self.assertEqual(run.main(["--suite", "all"]), 2)
        client_type.assert_not_called()

    def test_cli_rejects_an_unknown_suite(self):
        """Only checked-in classify, route, and combined suites are accepted."""
        run = importlib.import_module("evals.run")
        with self.assertRaises(SystemExit) as raised, redirect_stderr(io.StringIO()):
            run.main(["--suite", "unapproved"])
        self.assertEqual(raised.exception.code, 2)


class TestEvalReportPrivacyPolicy(unittest.TestCase):
    def test_local_eval_report_directory_is_gitignored(self):
        """Generated local evaluation reports must not be staged accidentally."""
        gitignore = Path(__file__).resolve().parents[1] / ".gitignore"
        self.assertIn("evals/reports/", gitignore.read_text(encoding="utf-8").splitlines())


if __name__ == "__main__":
    unittest.main()
