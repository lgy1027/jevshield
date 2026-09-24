import importlib.util
import os
from pathlib import Path
import asyncio
import unittest
from unittest.mock import patch

from jevshield import SecurityViolationError
from jevshield.models import Evaluation
from jevshield.rules import RuleOutcome
from jevshield.runtime import ChoiceAnswer, DecisionStatus


ROOT = Path(__file__).resolve().parents[1]


def load_example(filename):
    path = ROOT / "examples" / filename
    spec = importlib.util.spec_from_file_location(filename[:-3], path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DemoClient:
    def __init__(self, answer):
        self.answer = answer
        self.states = []

    def choose(self, state, question):
        self.states.append(state)
        return self.answer

    def evaluate_context(self, context, policy):
        return Evaluation(risk_level="safe", confidence=1.0, source="test")


class SequenceDemoClient(DemoClient):
    def __init__(self, answers):
        self.answers = list(answers)
        self.states = []

    def choose(self, state, question):
        self.states.append(state)
        return self.answers.pop(0)


def resolved(action, reason="reviewed"):
    return ChoiceAnswer(
        action, 0.9, DecisionStatus.RESOLVED, 1.0, "test", reason
    )


class TestLiveExampleEntrypoints(unittest.TestCase):
    def test_async_and_sql_example_stays_offline_and_fast_denies(self):
        """Changing the example client to ambient lookup must fail this test."""
        with patch.dict(os.environ, {"JEV_API_KEY": "live-key"}):
            example = load_example("01_async_and_sql.py")

        self.assertTrue(example.demo_client.is_mock_mode)
        self.assertEqual(
            example.execute_sql_query("SELECT id FROM users WHERE id = 42;"),
            "Query ok: SELECT id FROM users WHERE id = 42;",
        )

        def unexpected_evaluation(*_args, **_kwargs):
            raise AssertionError("Fast-Deny must run before the evaluator")

        async def unexpected_async_evaluation(*_args, **_kwargs):
            raise AssertionError("Fast-Deny must run before the evaluator")

        example.demo_client.evaluate_context = unexpected_evaluation
        example.demo_client.aevaluate_context = unexpected_async_evaluation
        with self.assertRaises(SecurityViolationError) as sql_error:
            example.execute_sql_query("DROP TABLE users;")
        self.assertEqual(sql_error.exception.rule_result.outcome, RuleOutcome.DENY)
        self.assertFalse(sql_error.exception.decision.network_called)
        with self.assertRaises(SecurityViolationError) as shell_error:
            asyncio.run(example.async_bash_executor("rm -rf /var/lib/docker"))
        self.assertEqual(shell_error.exception.rule_result.outcome, RuleOutcome.DENY)
        self.assertFalse(shell_error.exception.decision.network_called)

    def test_langchain_example_stays_offline_and_fast_denies(self):
        """Changing the wrapper client to ambient lookup must fail this test."""
        with patch.dict(os.environ, {"JEV_API_KEY": "live-key"}):
            example = load_example("02_langchain_integration.py")

        self.assertTrue(example.demo_client.is_mock_mode)
        guarded_delete, guarded_list = example.build_guarded_tools()

        self.assertIn("app.py", guarded_list.invoke({"path": "/workspace"}))

        def unexpected_evaluation(*_args, **_kwargs):
            raise AssertionError("Fast-Deny must run before the evaluator")

        example.demo_client.evaluate_context = unexpected_evaluation
        with self.assertRaises(SecurityViolationError) as error:
            guarded_delete.invoke({"bucket_name": "prod-backups", "force": True})
        self.assertEqual(error.exception.rule_result.outcome, RuleOutcome.DENY)
        self.assertFalse(error.exception.decision.network_called)

    def test_custom_client_example_keeps_the_demo_offline_and_guarded(self):
        with patch.dict(os.environ, {"JEV_API_KEY": "live-key"}):
            example = load_example("03_custom_client.py")

        self.assertTrue(example.enterprise_client.is_mock_mode)
        self.assertEqual(
            example.modify_user_role(1001, "superuser_admin"),
            "User 1001 set to superuser_admin",
        )

    def test_prompt_calibration_example_aggregates_each_candidate_separately(self):
        path = ROOT / "examples" / "09_live_multi_agent_prompt_calibration_eval.py"
        self.assertTrue(path.is_file())
        example = load_example(path.name)
        reports = {
            "baseline": iter(
                (
                    {
                        "route_total": 2,
                        "route_status_counts": {"resolved": 1, "uncertain": 1},
                        "handoff_action_counts": {"continue": 2},
                        "handoff_count": 1,
                        "expected_route_matches": 1,
                        "full_chain_completed": False,
                    },
                )
            ),
            "explicit_coding_task": iter(
                (
                    {
                        "route_total": 2,
                        "route_status_counts": {"resolved": 2},
                        "handoff_action_counts": {"continue": 3},
                        "handoff_count": 2,
                        "expected_route_matches": 2,
                        "full_chain_completed": True,
                    },
                )
            ),
            "coding_exclusive": iter(
                (
                    {
                        "route_total": 2,
                        "route_status_counts": {"resolved": 2},
                        "handoff_action_counts": {"continue": 3},
                        "handoff_count": 2,
                        "expected_route_matches": 1,
                        "full_chain_completed": True,
                    },
                )
            ),
        }
        calls = []

        def run_candidate(candidate_id):
            calls.append(candidate_id)
            return next(reports[candidate_id])

        report = example.run_prompt_calibration(run_candidate, runs=1)

        self.assertEqual(report["runs_per_candidate"], 1)
        self.assertEqual(
            set(report["candidates"]),
            {"baseline", "explicit_coding_task", "coding_exclusive"},
        )
        self.assertEqual(
            report["candidates"]["explicit_coding_task"]["full_chain_count"], 1
        )
        self.assertEqual(
            report["candidates"]["baseline"]["route_status_counts"],
            {"resolved": 1, "uncertain": 1},
        )
        self.assertEqual(calls, ["baseline", "explicit_coding_task", "coding_exclusive"])

    def test_default_handoff_prompt_matches_the_selected_calibration_candidate(self):
        single_run = load_example("07_live_multi_agent_handoff_eval.py")
        calibration = load_example("09_live_multi_agent_prompt_calibration_eval.py")

        candidate = calibration.CANDIDATES[calibration.SELECTED_CANDIDATE_ID]

        self.assertEqual(single_run.REQUESTS[1], candidate["second_request"])
        self.assertEqual(
            single_run.ROUTES["coding"].description, candidate["coding_description"]
        )

    def test_multi_agent_handoff_stability_example_aggregates_safe_run_reports(self):
        path = ROOT / "examples" / "08_live_multi_agent_handoff_stability_eval.py"
        self.assertTrue(path.is_file())
        example = load_example(path.name)
        reports = iter(
            (
                {
                    "route_total": 2,
                    "route_status_counts": {"resolved": 2},
                    "handoff_action_counts": {"continue": 3},
                    "handoff_count": 2,
                    "expected_route_matches": 2,
                    "full_chain_completed": True,
                },
                {
                    "route_total": 1,
                    "route_status_counts": {"uncertain": 1},
                    "handoff_action_counts": {},
                    "handoff_count": 0,
                    "expected_route_matches": 0,
                    "full_chain_completed": False,
                },
            )
        )

        report = example.run_stability_evaluation(lambda: next(reports), runs=2)

        self.assertEqual(
            report,
            {
                "runs": 2,
                "route_total": 3,
                "route_status_counts": {"resolved": 2, "uncertain": 1},
                "handoff_action_counts": {"continue": 3},
                "full_chain_count": 1,
                "expected_route_matches": 2,
            },
        )

    def test_multi_agent_handoff_example_exposes_a_safe_aggregator(self):
        path = ROOT / "examples" / "07_live_multi_agent_handoff_eval.py"
        self.assertTrue(path.is_file())
        self.assertTrue(callable(load_example(path.name).run_live_evaluation))

    def test_multi_agent_handoff_live_eval_routes_twice_and_returns_to_main(self):
        example = load_example("07_live_multi_agent_handoff_eval.py")
        client = SequenceDemoClient([resolved("research"), resolved("coding")])

        report = example.run_live_evaluation(client)

        self.assertEqual(
            set(report),
            {
                "route_total",
                "route_status_counts",
                "handoff_action_counts",
                "handoff_count",
                "expected_route_matches",
                "full_chain_completed",
            },
        )
        self.assertEqual(report["route_total"], 2)
        self.assertEqual(report["route_status_counts"], {"resolved": 2})
        self.assertEqual(report["handoff_action_counts"], {"continue": 3})
        self.assertEqual(report["handoff_count"], 2)
        self.assertEqual(report["expected_route_matches"], 2)
        self.assertTrue(report["full_chain_completed"])
        self.assertEqual(len(client.states), 2)
        self.assertNotIn("delivery policy", repr(report).lower())

    def test_multi_agent_handoff_live_eval_stops_after_an_uncertain_first_route(self):
        example = load_example("07_live_multi_agent_handoff_eval.py")
        client = SequenceDemoClient(
            [
                ChoiceAnswer(
                    None,
                    0.6,
                    DecisionStatus.UNCERTAIN,
                    1.0,
                    "test",
                    "raw-route-reason-must-not-escape",
                )
            ]
        )

        report = example.run_live_evaluation(client)

        self.assertEqual(report["route_total"], 1)
        self.assertEqual(report["route_status_counts"], {"uncertain": 1})
        self.assertEqual(report["handoff_action_counts"], {})
        self.assertEqual(report["handoff_count"], 0)
        self.assertEqual(report["expected_route_matches"], 0)
        self.assertFalse(report["full_chain_completed"])
        self.assertEqual(len(client.states), 1)
        self.assertNotIn("raw-route-reason-must-not-escape", repr(report))

    def test_multi_agent_handoff_live_eval_stops_after_an_unavailable_second_route(self):
        example = load_example("07_live_multi_agent_handoff_eval.py")
        client = SequenceDemoClient(
            [
                resolved("research"),
                ChoiceAnswer(
                    None,
                    0.0,
                    DecisionStatus.UNAVAILABLE,
                    1.0,
                    "timeout",
                    "raw-unavailable-reason-must-not-escape",
                ),
            ]
        )

        report = example.run_live_evaluation(client)

        self.assertEqual(report["route_total"], 2)
        self.assertEqual(
            report["route_status_counts"], {"resolved": 1, "unavailable": 1}
        )
        self.assertEqual(report["handoff_action_counts"], {"continue": 2})
        self.assertEqual(report["handoff_count"], 1)
        self.assertEqual(report["expected_route_matches"], 1)
        self.assertFalse(report["full_chain_completed"])
        self.assertEqual(len(client.states), 2)
        self.assertNotIn("raw-unavailable-reason-must-not-escape", repr(report))

    def test_live_evaluation_example_exposes_a_safe_aggregator(self):
        path = ROOT / "examples" / "06_live_loop_review_eval.py"
        self.assertTrue(path.is_file())
        self.assertTrue(callable(load_example(path.name).run_live_evaluation))

    def test_live_evaluation_counts_semantic_results_and_local_control(self):
        example = load_example("06_live_loop_review_eval.py")
        client = DemoClient(
            resolved("ask_for_help", reason="sk-eval-reason-must-not-escape")
        )

        report = example.run_live_evaluation(client)

        self.assertEqual(
            set(report),
            {"semantic_total", "status_counts", "action_counts", "local_action"},
        )
        self.assertEqual(report["semantic_total"], 3)
        self.assertEqual(report["status_counts"], {"resolved": 3})
        self.assertEqual(report["action_counts"], {"ask_for_help": 3})
        self.assertEqual(report["local_action"], "stop_stalled")
        self.assertEqual(len(client.states), 3)
        self.assertNotIn("sk-live-example-secret", repr(report))
        self.assertNotIn("sk-eval-reason-must-not-escape", repr(report))
        for scenario in example.SCENARIOS:
            self.assertNotIn(scenario[1], repr(report))
            if scenario[4] is not None:
                self.assertNotIn(scenario[4], repr(report))

    def test_agent_example_exposes_a_testable_runner(self):
        path = ROOT / "examples" / "04_live_agent_loop.py"
        self.assertTrue(path.is_file())
        self.assertTrue(callable(load_example(path.name).run_demo))

    def test_rag_example_exposes_a_testable_runner(self):
        path = ROOT / "examples" / "05_live_rag_checkpoint.py"
        self.assertTrue(path.is_file())
        self.assertTrue(callable(load_example(path.name).run_demo))

    def test_agent_stops_after_a_real_reviewer_recommendation(self):
        example = load_example("04_live_agent_loop.py")
        client = DemoClient(resolved("ask_for_help"))

        result = example.run_demo(client)

        self.assertEqual(result.action.value, "ask_for_help")
        self.assertEqual(len(client.states), 1)

    def test_rag_sends_only_derived_evidence_summary_to_reviewer(self):
        example = load_example("05_live_rag_checkpoint.py")
        client = DemoClient(resolved("ask_for_help"))

        result = example.run_demo(client)

        self.assertEqual(result.action.value, "ask_for_help")
        self.assertEqual(len(client.states), 1)
        self.assertNotIn("sk-live-example-secret", client.states[0])
        self.assertNotIn(example.SOURCE_DOCUMENTS[0], client.states[0])
        self.assertNotIn(example.SOURCE_DOCUMENTS[1], client.states[0])

    def test_examples_reject_an_unconfigured_live_client(self):
        for filename in (
            "04_live_agent_loop.py",
            "05_live_rag_checkpoint.py",
            "06_live_loop_review_eval.py",
            "07_live_multi_agent_handoff_eval.py",
        ):
            with self.subTest(filename=filename):
                example = load_example(filename)
                with patch.dict(os.environ, {}, clear=True):
                    with self.assertRaisesRegex(RuntimeError, "JEV_API_KEY"):
                        example.require_live_client()
