import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from jevshield.models import Evaluation
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
            {"route_total", "route_status_counts", "handoff_action_counts", "handoff_count"},
        )
        self.assertEqual(report["route_total"], 2)
        self.assertEqual(report["route_status_counts"], {"resolved": 2})
        self.assertEqual(report["handoff_action_counts"], {"continue": 3})
        self.assertEqual(report["handoff_count"], 2)
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
