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


def resolved(action):
    return ChoiceAnswer(
        action, 0.9, DecisionStatus.RESOLVED, 1.0, "test", "reviewed"
    )


class TestLiveExampleEntrypoints(unittest.TestCase):
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
        for filename in ("04_live_agent_loop.py", "05_live_rag_checkpoint.py"):
            with self.subTest(filename=filename):
                example = load_example(filename)
                with patch.dict(os.environ, {}, clear=True):
                    with self.assertRaisesRegex(RuntimeError, "JEV_API_KEY"):
                        example.require_live_client()
